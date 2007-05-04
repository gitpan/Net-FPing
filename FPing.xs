#define _POSIX_C_SOURCE 199309
#define _GNU_SOURCE 1

#define IPV6 1 // if you get compilation problems try to disable IPv6

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <pthread.h>

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <poll.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __linux
# include <linux/icmp.h>
#endif
#if IPV6
# include <netinet/icmp6.h>
#endif

#define ICMP4_ECHO       8
#define ICMP4_ECHO_REPLY 0
#define ICMP6_ECHO       128
#define ICMP6_ECHO_REPLY 129

#define DRAIN_INTERVAL .000001 // how long to wait when sendto returns ENOBUFS, in seconds
#define MIN_INTERVAL   .000001 // minimum packet send interval, in seconds

#define HDR_SIZE_IP4  20
#define HDR_SIZE_IP6  48

//TODO: xread/xwrite for atomicity? we currently rely on the fact that the pip biffersize divides exactly by pointer sizes

typedef uint8_t addr_t[16];

typedef double tstamp;

tstamp
NOW ()
{
  struct timeval tv;
  gettimeofday (&tv, 0);
  return tv.tv_sec + tv.tv_usec * 0.000001;
}

typedef struct {
  int family;
  addr_t lo, hi;
  double interval;
  tstamp next;
} RANGE;

typedef struct {
  SV *id;
  double interval;
  int nranges;
  RANGE *ranges;
  uint32_t payload;
} REQ;

typedef struct {
  uint8_t version_ihl;
  uint8_t tos;
  uint16_t tot_len;

  uint16_t id;
  uint16_t flags;

  uint8_t ttl;
  uint8_t protocol;
  uint16_t cksum;

  uint32_t src;
  uint32_t dst;
} IP4HDR;

typedef struct {
  uint8_t version;
  uint8_t x1, x2, x3;

  uint16_t payload_len;
  uint8_t nxt_hdr;
  uint8_t hop_limit;

  uint8_t src[16];
  uint8_t dst[16];
} IP6HDR;

#define MAGIC 0xca4c

typedef struct {
  uint8_t type, code;
  uint16_t cksum;
  uint16_t id, seq;
  uint32_t payload;
  tstamp stamp; // be careful when accessing this
} PKT;

static pthread_t pthrid;
static int thr_send[2]; // send to worker
static int thr_recv[2]; // receive from worker

static int icmp4_fd, icmp6_fd;

static AV *cbs;

static uint16_t
icmp_cksum (void *data, unsigned int len)
{
  register int sum = 0;
  uint16_t *wp;

  assert (~len & 1);

  for (wp = (uint16_t *)data; len; wp++, len -= 2)
    sum += *wp;

  sum = (sum >> 16) + (sum & 0xffff);   /* add high 16 to low 16 */
  sum += sum >> 16;                     /* add carry */

  return ~sum;
}

static void
inc_addr (addr_t *addr)
{
  int len = sizeof (addr_t) - 1;

  do
    {
      if ((*addr)[len] != 0xff)
        {
          ++(*addr)[len];
          break;
        }

      (*addr)[len] = 0;
    }
  while (len--);
}

static void *
ping_proc (void *unused)
{
  PKT pkt;
  struct sockaddr_in sa4;
#if IPV6
  struct sockaddr_in6 sa6;
#endif

  memset (&pkt, 0, sizeof (pkt));

  memset (&sa4, 0, sizeof (sa4));
  sa4.sin_family  = AF_INET;
  sa4.sin_port    = 0;
#if IPV6
  memset (&sa6, 0, sizeof (sa6));
  sa6.sin6_family = AF_INET6;
  sa6.sin6_port   = 0;
#endif

  for (;;)
    {
      REQ *req;
      int len = read (thr_send [0], &req, sizeof (req));

      if (!len)
        pthread_exit (0);
      else if (len != sizeof (req))
        {
          perror ("Net::FPing: short reead or read error");
          pthread_exit ((void *)-1);
        }

      //TODO: bind to source address

      pkt.code    = 0;
      pkt.id      = (uint16_t)MAGIC;
      pkt.seq     = (uint16_t)~MAGIC;
      pkt.payload = req->payload;

      tstamp now = NOW ();
      tstamp next = now;

      {
        int r;
        for (r = req->nranges; r--; )
          inc_addr (&req->ranges [r].hi);
      }

      while (req->nranges)
        {
          RANGE *range = req->ranges;

          if (!memcmp (&range->lo, &range->hi, sizeof (addr_t)))
            req->ranges [0] = req->ranges [--req->nranges];
          else
            {
              // ranges [0] is always the next range to ping
              tstamp wait = range->next - now;

              // compare with the global frequency limit
              {
                tstamp diff = next - now;

                if (wait < diff)
                  wait = diff;
                else if (range)
                  next = range->next;
              }

              if (wait > 0.)
                {
                  struct timespec ts;

                  ts.tv_sec  = wait;
                  ts.tv_nsec = (wait - ts.tv_sec) * 1000000000.;

                  nanosleep (&ts, 0);
                }

              now = NOW ();

              pkt.stamp = now;
              pkt.cksum = 0;

              if (range->family == AF_INET)
                {
                  pkt.type  = ICMP4_ECHO;
                  pkt.cksum = icmp_cksum (&pkt, sizeof (pkt));

                  memcpy (&sa4.sin_addr,
                          sizeof (addr_t) - sizeof (sa4.sin_addr) + (char *)&range->lo,
                          sizeof (sa4.sin_addr));

                  if (sendto (icmp4_fd, &pkt, sizeof (pkt), 0, (struct sockaddr *)&sa4, sizeof (sa4)) > 0)
                    errno = 0;
                }
              else
                {
#if IPV6
                  pkt.type = ICMP6_ECHO;

                  memcpy (&sa6.sin6_addr,
                          sizeof (addr_t) - sizeof (sa6.sin6_addr) + (char *)&range->lo,
                          sizeof (sa6.sin6_addr));

                  if (sendto (icmp6_fd, &pkt, sizeof (pkt), 0, (struct sockaddr *)&sa6, sizeof (sa6)) > 0)
                    errno = 0;
#endif
                }

              if (errno == ENOBUFS)
                {
                  struct timespec ts;

                  ts.tv_sec  = 0;
                  ts.tv_nsec = DRAIN_INTERVAL * 1000000000;

                  nanosleep (&ts, 0);
                }
              else
                {
                  inc_addr (&range->lo);

                  range->next = next;
                  range->next += range->interval;
                }

              next += req->interval;
            }

          // make a downheap operation
          int k = 0;
          int n = 0;
          for (;;)
            {
              ++n;
              int j = k * 2 + 1;

              if (j >= req->nranges)
                break;
              else if (j < req->nranges - 1)
                if (req->ranges [j].next > req->ranges [j + 1].next)
                  ++j;

              if (req->ranges [j].next >= req->ranges [k].next)
                break;

              RANGE temp = req->ranges [k];
              req->ranges [k] = req->ranges [j];
              req->ranges [j] = temp;

              k = j;
            }
        }

      write (thr_recv [1], &req, sizeof (req));
    }

  return 0;
}

static void
feed_reply (AV *res_av)
{
  if (av_len (res_av) < 0)
    return;

  dSP;
  SV *res = sv_2mortal (newRV_inc ((SV *)res_av));
  int i;

  ENTER;
  SAVETMPS;

  for (i = av_len (cbs) + 1; i--; )
    {
      SV *cb = *av_fetch (cbs, i, 1);

      PUSHMARK (SP);
      XPUSHs (res);
      PUTBACK;
      call_sv (cb, G_DISCARD | G_VOID);
    }

  FREETMPS;
  LEAVE;
}

static void
boot ()
{
  sigset_t fullsigset, oldsigset;
  pthread_attr_t attr;

  if (pipe (thr_send) < 0)
    croak ("Net::FPing: unable to create send pipe");

  if (pipe (thr_recv) < 0)
    croak ("Net::FPing: unable to create receive pipe");

  icmp4_fd = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
#ifdef ICMP_FILTER
  {
    struct icmp_filter oval;
    oval.data = 0xffffffff & ~(1 << ICMP4_ECHO_REPLY);
    setsockopt (icmp4_fd, SOL_RAW, ICMP_FILTER, &oval, sizeof oval);
  }
#endif

#if IPV6
  icmp6_fd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
# ifdef ICMP6_FILTER
  {
    struct icmp6_filter oval;
    ICMP6_FILTER_SETBLOCKALL (&oval);
    ICMP6_FILTER_SETPASS (ICMP6_ECHO_REPLY, &oval);
    setsockopt (icmp6_fd, IPPROTO_ICMPV6, ICMP6_FILTER, &oval, sizeof oval);
  }
# endif
#endif

  pthread_attr_init (&attr);
  pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED);
#ifdef PTHREAD_SCOPE_PROCESS
  pthread_attr_setscope (&attr, PTHREAD_SCOPE_PROCESS);
#endif

  sigfillset (&fullsigset);

  pthread_sigmask (SIG_SETMASK, &fullsigset, &oldsigset);

  if (pthread_create (&pthrid, &attr, ping_proc, 0))
    croak ("Net::FPing: unable to create pinger thread");

  pthread_sigmask (SIG_SETMASK, &oldsigset, 0);

  sv_setiv (get_sv ("Net::FPing::THR_REQ_FD", 1), thr_send [1]);
  sv_setiv (get_sv ("Net::FPing::THR_RES_FD", 1), thr_recv [0]);

  sv_setiv (get_sv ("Net::FPing::ICMP4_FD", 1), icmp4_fd);
  sv_setiv (get_sv ("Net::FPing::ICMP6_FD", 1), icmp6_fd);
}

MODULE = Net::FPing		PACKAGE = Net::FPing

BOOT:
{
  HV *stash = gv_stashpv ("Net::FPing", 1);

  cbs = get_av ("Net::FPing::CB", 1);

  boot ();

  newCONSTSUB (stash, "ipv4_supported", newSViv (icmp4_fd >= 0));
  newCONSTSUB (stash, "ipv6_supported", newSViv (icmp6_fd >= 0));

  newCONSTSUB (stash, "icmp4_pktsize", newSViv (HDR_SIZE_IP4 + sizeof (PKT)));
  newCONSTSUB (stash, "icmp6_pktsize", newSViv (HDR_SIZE_IP6 + sizeof (PKT)));
}

PROTOTYPES: DISABLE

SV *
_req_icmp_ping (SV *ranges, NV interval, U32 payload, SV *id)
	CODE:
{
  	if (!SvROK (ranges) || SvTYPE (SvRV (ranges)) != SVt_PVAV)
          croak ("address ranges must be given as arrayref with lo, hi pairs");

        AV *rav = (AV *)SvRV (ranges);
        int nranges = av_len (rav) + 1;

        REQ *req = malloc (sizeof (REQ));
        int i;

        if (interval < MIN_INTERVAL)
          interval = MIN_INTERVAL;

        req->id       = newSVsv (id);
        req->interval = interval;
        req->payload  = payload;
        req->nranges  = nranges;
        req->ranges   = (RANGE *)malloc (nranges * sizeof (RANGE));

        while (nranges--)
          {
            SV *sv = *av_fetch (rav, nranges, 1);

            if (!SvROK (sv) || SvTYPE (SvRV (sv)) != SVt_PVAV)
              croak ("address range must be given as arrayref with lo, hi, interval arrayrefs");

            AV *av = (AV *)SvRV (sv);
            RANGE *r = req->ranges + nranges;

            SV *lo = *av_fetch (av, 0, 1);
            SV *hi = *av_fetch (av, 1, 1);

            sv_utf8_downgrade (lo, 0);
            sv_utf8_downgrade (hi, 0);

            memset (&r->lo, 0, sizeof (addr_t));
            memset (&r->hi, 0, sizeof (addr_t));

            if (SvPOKp (lo) && SvPOKp (hi))
              {
                if (SvCUR (lo) != SvCUR (hi))
                  croak ("addresses in range must be of the same size (either 4 or 16 bytes)");

                if (SvCUR (lo) == 4)
                  {
                    r->family = AF_INET;
                    memcpy (sizeof (addr_t) - 4 + (char *)&r->lo, SvPVX (lo), 4);
                    memcpy (sizeof (addr_t) - 4 + (char *)&r->hi, SvPVX (hi), 4);
                  }
                else if (SvCUR (lo) == 16)
                  {
#if IPV6
                    r->family = AF_INET6;
                    memcpy (&r->lo, SvPVX (lo), sizeof (addr_t));
                    memcpy (&r->hi, SvPVX (hi), sizeof (addr_t));
#else
                    croak ("IPv6 not supported in this configuration");
#endif
                  }
                else
                  croak ("addresses in range must be either 4 (IPv4) or 16 (IPV6) bytes in length");
              }
            else if (SvIOK (lo) && SvIOK (hi))
              {
                r->family = AF_INET;

                uint32_t addr;
                addr = htonl (SvUV (lo)); memcpy (sizeof (addr_t) - 4 + (char *)&r->lo, &addr, 4);
                addr = htonl (SvUV (hi)); memcpy (sizeof (addr_t) - 4 + (char *)&r->hi, &addr, 4);
              }
            else
              croak ("addresses in range must be strings with either 4 (IPv4) or 16 (IPv6) octets");

            if (r->family == AF_INET)
              {
                if (icmp4_fd < 0)
                  croak ("Net::FPing: IPv4 ping support not available on this system");
              }
            else
              {
                if (icmp6_fd < 0)
                  croak ("Net::FPing: IPv6 ping support not available on this system");
              }

            r->interval = SvNV (*av_fetch (av, 2, 1));

            if (r->interval < req->interval)
              r->interval = req->interval;

            r->next = 0.;
          }

        RETVAL = newSVpvn ((char *)&req, sizeof (req));
}
	OUTPUT:
        RETVAL

SV *
_read_res ()
	CODE:
{
        REQ *req;

        if (read (thr_recv [0], &req, sizeof (req)) != sizeof (req))
          RETVAL = &PL_sv_undef;

        RETVAL = req->id;
        free (req->ranges);
        free (req);
}
        OUTPUT:
        RETVAL

void
_recv_icmp4 (...)
	CODE:
{
	char buf [512];
        struct sockaddr_in sa;
        socklen_t sl = sizeof (sa);
        AV *res_av = av_len (cbs) < 0 ? 0 : (AV *)sv_2mortal ((SV *)newAV ());
        tstamp now = NOW ();

        for (;;)
          {
            int len = recvfrom (icmp4_fd, buf, sizeof (buf), MSG_DONTWAIT | MSG_TRUNC, &sa, &sl);

            if (len <= HDR_SIZE_IP4)
              break;

            IP4HDR *iphdr = (IP4HDR *)buf;

            int hdrlen = (iphdr->version_ihl & 15) * 4;
            int totlen = ntohs (iphdr->tot_len);

            // packet corrupt?
            if (!res_av
                || totlen > len
                || iphdr->protocol != IPPROTO_ICMP
                || hdrlen < HDR_SIZE_IP4 || hdrlen + sizeof (PKT) != totlen)
              continue;

            PKT *pkt = (PKT *)(buf + hdrlen);

            if (pkt->type != ICMP4_ECHO_REPLY
                || pkt->id  != (uint16_t) MAGIC
                || pkt->seq != (uint16_t)~MAGIC
                || !isnormal (pkt->stamp))
              continue;

            AV *av = newAV ();
            av_push (av, newSVpvn ((char *)&sa.sin_addr, 4));
            av_push (av, newSVnv (now - pkt->stamp));
            av_push (av, newSVuv (pkt->payload));

            av_push (res_av, newRV_noinc ((SV *)av));
          }

        if (res_av)
          feed_reply (res_av);
}

void
_recv_icmp6 (...)
	CODE:
{
        struct sockaddr_in6 sa;
        socklen_t sl = sizeof (sa);
        AV *res_av = av_len (cbs) < 0 ? 0 : (AV *)sv_2mortal ((SV *)newAV ());
        PKT pkt;
        tstamp now = NOW ();

        for (;;)
          {
            int len = recvfrom (icmp6_fd, &pkt, sizeof (pkt), MSG_DONTWAIT | MSG_TRUNC, &sa, &sl);

            if (len != sizeof (PKT))
              break;

            if (!res_av
                || pkt.type != ICMP6_ECHO_REPLY
                || pkt.id  != (uint16_t) MAGIC
                || pkt.seq != (uint16_t)~MAGIC
                || !isnormal (pkt.stamp))
              continue;

            AV *av = newAV ();
            av_push (av, newSVpvn ((char *)&sa.sin6_addr, 16));
            av_push (av, newSVnv (now - pkt.stamp));
            av_push (av, newSVuv (pkt.payload));

            av_push (res_av, newRV_noinc ((SV *)av));
          }

        if (res_av)
          feed_reply (res_av);
}

