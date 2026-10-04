/*********************************************************************
 *
 * File        :  $Source: /cvsroot/ijbswa/current/jbsockets.c,v $
 *
 * Purpose     :  Contains wrappers for system-specific sockets code,
 *                so that the rest of Privoxy can be more
 *                OS-independent.  Contains #ifdefs to make this work
 *                on many platforms.
 *
 * Copyright   :  Written by and Copyright (C) 2001-2026 the
 *                Privoxy team. https://www.privoxy.org/
 *
 *                Based on the Internet Junkbuster originally written
 *                by and Copyright (C) 1997 Anonymous Coders and
 *                Junkbusters Corporation.  http://www.junkbusters.com
 *
 *                This program is free software; you can redistribute it
 *                and/or modify it under the terms of the GNU General
 *                Public License as published by the Free Software
 *                Foundation; either version 2 of the License, or (at
 *                your option) any later version.
 *
 *                This program is distributed in the hope that it will
 *                be useful, but WITHOUT ANY WARRANTY; without even the
 *                implied warranty of MERCHANTABILITY or FITNESS FOR A
 *                PARTICULAR PURPOSE.  See the GNU General Public
 *                License for more details.
 *
 *                The GNU General Public License should be included with
 *                this file.  If not, you can view it at
 *                http://www.gnu.org/copyleft/gpl.html
 *                or write to the Free Software Foundation, Inc., 59
 *                Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *********************************************************************/


#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>

#ifdef _WIN32

#ifndef STRICT
#define STRICT
#endif
#include <winsock2.h>
#include <windows.h>
#include <sys/timeb.h>
#include <io.h>

#else

#include <unistd.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <sys/socket.h>

#ifndef __BEOS__
#include <netinet/tcp.h>
#include <arpa/inet.h>
#else
#include <socket.h>
#endif

#endif

/* For clock_gettime() and gettimeofday() */
#include <time.h>
#include <sys/time.h>

#ifdef HAVE_POLL
#ifdef __GLIBC__
#include <sys/poll.h>
#else
#include <poll.h>
#endif /* def __GLIBC__ */
#endif /* HAVE_POLL */

#include "project.h"

/* For mutex semaphores only */
#include "jcc.h"

#include "jbsockets.h"
#include "filters.h"
#include "errlog.h"
#include "miscutil.h"

/* Mac OSX doesn't define AI_NUMERICSESRV */
#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0
#endif

/*
 * Maximum number of gethostbyname(_r) retries in case of
 * soft errors (TRY_AGAIN).
 * XXX: Does it make sense to make this a config option?
 */
#define MAX_DNS_RETRIES 10

#ifdef HAVE_RFC2553
static jb_socket rfc2553_connect_to(const char *host, int portnum, struct client_state *csp);
#else
static jb_socket no_rfc2553_connect_to(const char *host, int portnum, struct client_state *csp);
#endif

/*********************************************************************
 *
 * Function    :  set_no_delay_flag
 *
 * Description :  Disables the Nagle algorithm (TCP send coalescence)
 *                for the given socket.
 *
 * Parameters  :
 *          1  :  fd = The file descriptor to operate on
 *
 * Returns     :  void
 *
 *********************************************************************/
static void set_no_delay_flag(int fd)
{
#ifdef TCP_NODELAY
   int mi = 1;

   if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &mi, sizeof(int)))
   {
      log_error(LOG_LEVEL_ERROR,
         "Failed to disable TCP coalescence for socket %d", fd);
   }
#else
#warning set_no_delay_flag() is a nop due to lack of TCP_NODELAY
#endif /* def TCP_NODELAY */
}

/*********************************************************************
 *
 * Function    :  connect_to
 *
 * Description :  Open a socket and connect to it.  Will check
 *                that this is allowed according to ACL.
 *
 * Parameters  :
 *          1  :  host = hostname to connect to
 *          2  :  portnum = port to connect to (XXX: should be unsigned)
 *          3  :  csp = Current client state (buffers, headers, etc...)
 *
 * Returns     :  JB_INVALID_SOCKET => failure, else it is the socket
 *                file descriptor.
 *
 *********************************************************************/
jb_socket connect_to(const char *host, int portnum, struct client_state *csp)
{
   jb_socket fd;
   int forwarded_connect_retries = 0;

   do
   {
      /*
       * XXX: The whole errno overloading is ridiculous and should
       *      be replaced with something sane and thread safe
       */
      /* errno = 0;*/
#ifdef HAVE_RFC2553
      fd = rfc2553_connect_to(host, portnum, csp);
#else
      fd = no_rfc2553_connect_to(host, portnum, csp);
#endif
      if ((fd != JB_INVALID_SOCKET) || (errno == EINVAL)
         || (csp->fwd == NULL)
         || ((csp->fwd->forward_host == NULL) && (csp->fwd->type == SOCKS_NONE)))
      {
         break;
      }
      forwarded_connect_retries++;
      if (csp->config->forwarded_connect_retries != 0)
      {
         log_error(LOG_LEVEL_ERROR,
            "Attempt %d of %d to connect to %s failed. Trying again.",
            forwarded_connect_retries, csp->config->forwarded_connect_retries + 1, host);
      }

   } while (forwarded_connect_retries < csp->config->forwarded_connect_retries);

   return fd;
}

#ifdef HAVE_RFC2553

/*
 * Number of milliseconds after which a single connection
 * attempt is considered to have failed.
 */
#define CONNECT_TIMEOUT_MSECS 30000

#ifndef HAVE_POLL
/* Only used as opaque pointer type if poll() isn't available. */
struct pollfd;
#endif

/*
 * Possible results of start_connection_attempt().
 */
enum connect_attempt_result
{
   CONNECT_ATTEMPT_FAILED,
   CONNECT_ATTEMPT_PENDING,
   CONNECT_ATTEMPT_CONNECTED
};

/*
 * State of a connection attempt to a single address.
 *
 * Used by rfc2553_connect_to() which may have several
 * attempts in flight at the same time (RFC 8305).
 */
struct connect_attempt
{
   /** The address to connect to. */
   const struct addrinfo *address;

   /** The socket used for the attempt or JB_INVALID_SOCKET. */
   jb_socket fd;

   /** Whether or not the attempt has been started but not completed yet. */
   int pending;

   /** Set by wait_for_connection_attempts() if the attempt completed. */
   int ready;

   /** The time at which the attempt was started. */
   struct timeval start_time;

#if !defined(_WIN32) && !defined(__BEOS__)
   /** The file status flags of the socket before it was made non-blocking. */
   int flags;
#endif

   /** Textual representation of the address. */
   char ip_addr_str[NI_MAXHOST];
};


/*********************************************************************
 *
 * Function    :  get_monotonic_time
 *
 * Description :  Gets the current time for the purpose of measuring
 *                time intervals. Uses a monotonic clock if available
 *                so that the intervals aren't affected by changes
 *                of the system time.
 *
 * Parameters  :
 *          1  :  now = Receives the current time.
 *
 * Returns     :  N/A
 *
 *********************************************************************/
static void get_monotonic_time(struct timeval *now)
{
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
   struct timespec ts;

   if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
   {
      now->tv_sec = ts.tv_sec;
      now->tv_usec = (suseconds_t)(ts.tv_nsec / 1000);
      return;
   }
#endif
   gettimeofday(now, NULL);
}


/*********************************************************************
 *
 * Function    :  msecs_since
 *
 * Description :  Returns the number of milliseconds that have
 *                passed since the given point in time.
 *
 * Parameters  :
 *          1  :  start = The point in time to compare against.
 *                        Has to come from get_monotonic_time().
 *
 * Returns     :  Number of milliseconds that passed since start.
 *
 *********************************************************************/
static long msecs_since(const struct timeval *start)
{
   struct timeval now;

   get_monotonic_time(&now);

   return (now.tv_sec - start->tv_sec) * 1000
      + (now.tv_usec - start->tv_usec) / 1000;
}


/*********************************************************************
 *
 * Function    :  get_socket_error
 *
 * Description :  Returns the error code of the socket call that
 *                just failed. On Windows the socket functions don't
 *                set errno.
 *
 * Parameters  :  None
 *
 * Returns     :  The error code.
 *
 *********************************************************************/
static int get_socket_error(void)
{
#ifdef _WIN32
   return WSAGetLastError();
#else
   return errno;
#endif
}


/*********************************************************************
 *
 * Function    :  socket_strerror
 *
 * Description :  Returns a textual representation of an error
 *                code returned by get_socket_error().
 *
 * Parameters  :
 *          1  :  error = The error code.
 *          2  :  buffer = Scratch space that may be used for the result.
 *          3  :  buffer_size = Size of buffer in bytes.
 *
 * Returns     :  The error text, possibly stored in buffer.
 *
 *********************************************************************/
#define SOCKET_STRERROR_BUFFER_SIZE 128
static const char *socket_strerror(int error, char *buffer, size_t buffer_size)
{
#ifdef _WIN32
   const char *text;
   size_t length;

   if (buffer_size == 0)
   {
      return "";
   }
   text = w32_socket_strerr(error, buffer, buffer_size);
   if (text != buffer)
   {
      strlcpy(buffer, text, buffer_size);
   }
   /* Remove the trailing period so the text can be embedded in a sentence. */
   length = strlen(buffer);
   if ((length > 0) && (buffer[length - 1] == '.'))
   {
      buffer[length - 1] = '\0';
   }
   return buffer;
#else
   (void)buffer;
   (void)buffer_size;
   return strerror(error);
#endif
}


/*********************************************************************
 *
 * Function    :  set_socket_blocking_mode
 *
 * Description :  Switches a socket between blocking and
 *                non-blocking mode.
 *
 * Parameters  :
 *          1  :  attempt = The connection attempt whose socket
 *                          to modify. Its flags member is used
 *                          to remember the original mode.
 *          2  :  blocking = TRUE to make the socket blocking,
 *                           FALSE to make it non-blocking.
 *
 * Returns     :  N/A
 *
 *********************************************************************/
static void set_socket_blocking_mode(struct connect_attempt *attempt,
   int blocking)
{
#if defined(_WIN32)
   u_long non_blocking = !blocking;

   ioctlsocket(attempt->fd, FIONBIO, &non_blocking);
#elif !defined(__BEOS__)
   if (!blocking)
   {
      attempt->flags = fcntl(attempt->fd, F_GETFL, 0);
      if (attempt->flags != -1)
      {
         fcntl(attempt->fd, F_SETFL, attempt->flags | O_NDELAY);
      }
   }
   else if (attempt->flags != -1)
   {
      fcntl(attempt->fd, F_SETFL, attempt->flags);
   }
#else
   (void)attempt;
   (void)blocking;
#endif
}


/*********************************************************************
 *
 * Function    :  order_addresses
 *
 * Description :  Distributes the addresses returned by getaddrinfo()
 *                to the connection attempts in the order the attempts
 *                should be made.
 *
 *                As described in RFC 8305 section 4 the addresses
 *                are sorted by alternating between address families,
 *                starting with the family of the first address, which
 *                is the family preferred by the resolver (RFC 6724).
 *                The order of the addresses within a family is
 *                preserved.
 *
 * Parameters  :
 *          1  :  result = The list returned by getaddrinfo().
 *          2  :  attempts = Array of connection attempts with
 *                           room for attempt_count entries.
 *          3  :  attempt_count = Maximum number of addresses to use.
 *
 * Returns     :  N/A
 *
 *********************************************************************/
static void order_addresses(const struct addrinfo *result,
   struct connect_attempt *attempts, int attempt_count)
{
   const struct addrinfo *first_family_address = result;
   const struct addrinfo *other_family_address = result;
   const int first_family = result->ai_family;
   int count = 0;

   while ((count < attempt_count)
      && ((first_family_address != NULL) || (other_family_address != NULL)))
   {
      /* Skip the addresses that belong to the other family */
      while ((first_family_address != NULL)
         && (first_family_address->ai_family != first_family))
      {
         first_family_address = first_family_address->ai_next;
      }
      if (first_family_address != NULL)
      {
         attempts[count++].address = first_family_address;
         first_family_address = first_family_address->ai_next;
      }

      /* Skip the addresses that belong to the first family */
      while ((other_family_address != NULL)
         && (other_family_address->ai_family == first_family))
      {
         other_family_address = other_family_address->ai_next;
      }
      if ((count < attempt_count) && (other_family_address != NULL))
      {
         attempts[count++].address = other_family_address;
         other_family_address = other_family_address->ai_next;
      }
   }
}


/*********************************************************************
 *
 * Function    :  start_connection_attempt
 *
 * Description :  Creates a socket and starts a non-blocking
 *                connection attempt to the attempt's address.
 *
 * Parameters  :
 *          1  :  csp = Current client state (buffers, headers, etc...)
 *          2  :  attempt = The connection attempt to start.
 *          3  :  socket_error = Receives the errno of the failure
 *                               in case the attempt fails.
 *
 * Returns     :  CONNECT_ATTEMPT_CONNECTED if the connection was
 *                established right away, CONNECT_ATTEMPT_PENDING
 *                if the attempt is in progress or
 *                CONNECT_ATTEMPT_FAILED if it failed.
 *
 *********************************************************************/
static enum connect_attempt_result start_connection_attempt(
   struct client_state *csp, struct connect_attempt *attempt,
   int *socket_error)
{
   const struct addrinfo *rp = attempt->address;
   jb_socket fd;
   int retval;
#ifdef FEATURE_ACL
   struct access_control_addr dst[1];
#endif /* def FEATURE_ACL */

   retval = getnameinfo(rp->ai_addr, rp->ai_addrlen, attempt->ip_addr_str,
      sizeof(attempt->ip_addr_str), NULL, 0, NI_NUMERICHOST);
   if (retval)
   {
      log_error(LOG_LEVEL_ERROR,
         "Failed to get the host name from the socket structure: %s",
         gai_strerror(retval));
      *socket_error = errno = EINVAL;
      return CONNECT_ATTEMPT_FAILED;
   }

#ifdef FEATURE_ACL
   memcpy(&dst->addr, rp->ai_addr, rp->ai_addrlen);
#ifdef ACL_DEBUG
   dst->addr_length = rp->ai_addrlen;
#endif

   if (block_acl(csp, dst))
   {
      *socket_error = errno = EPERM;
      return CONNECT_ATTEMPT_FAILED;
   }
#endif /* def FEATURE_ACL */

   fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
#ifdef _WIN32
   if (fd == JB_INVALID_SOCKET)
#else
   if (fd < 0)
#endif
   {
      *socket_error = get_socket_error();
      return CONNECT_ATTEMPT_FAILED;
   }

#ifndef HAVE_POLL
#ifndef _WIN32
   if (fd >= FD_SETSIZE)
   {
      log_error(LOG_LEVEL_ERROR,
         "Server socket number too high to use select(): %d >= %d",
         fd, FD_SETSIZE);
      close_socket(fd);
      *socket_error = EMFILE;
      return CONNECT_ATTEMPT_FAILED;
   }
#endif
#endif

#ifdef FEATURE_EXTERNAL_FILTERS
   mark_socket_for_close_on_execute(fd);
#endif

   set_no_delay_flag(fd);

   attempt->fd = fd;
   set_socket_blocking_mode(attempt, FALSE);
   get_monotonic_time(&attempt->start_time);

   while (connect(fd, rp->ai_addr, rp->ai_addrlen) == JB_INVALID_SOCKET)
   {
      int error = get_socket_error();

#ifdef _WIN32
      if (error == WSAEWOULDBLOCK)
#else /* ifndef _WIN32 */
      if (error == EINPROGRESS)
#endif /* ndef _WIN32 */
      {
         return CONNECT_ATTEMPT_PENDING;
      }

      if (error != EINTR)
      {
         *socket_error = error;
         close_socket(fd);
         attempt->fd = JB_INVALID_SOCKET;
         return CONNECT_ATTEMPT_FAILED;
      }
   }

   /*
    * connect() succeeded right away. This is expected on platforms
    * where the socket couldn't be made non-blocking and may also
    * happen for local addresses.
    */
   return CONNECT_ATTEMPT_CONNECTED;
}


/*********************************************************************
 *
 * Function    :  wait_for_connection_attempts
 *
 * Description :  Waits until at least one of the pending connection
 *                attempts completes (successfully or not) or the
 *                timeout expires. Completed attempts are marked as
 *                ready.
 *
 * Parameters  :
 *          1  :  attempts = Array of connection attempts.
 *          2  :  attempt_count = Number of entries in the array.
 *          3  :  timeout_msecs = Maximum number of milliseconds to wait.
 *          4  :  poll_fds = Scratch space for poll() with room for
 *                           attempt_count entries. Unused if poll()
 *                           isn't available.
 *
 * Returns     :  Number of attempts that are ready, 0 in case
 *                of a timeout or -1 on error with errno set.
 *
 *********************************************************************/
static int wait_for_connection_attempts(struct connect_attempt *attempts,
   int attempt_count, int timeout_msecs, struct pollfd *poll_fds)
{
   int i;
   int ready_count = 0;
   int retval;
#ifdef HAVE_POLL
   int poll_fd_count = 0;

   for (i = 0; i < attempt_count; i++)
   {
      attempts[i].ready = 0;
      if (attempts[i].pending)
      {
         poll_fds[poll_fd_count].fd = attempts[i].fd;
         poll_fds[poll_fd_count].events = POLLOUT;
         poll_fd_count++;
      }
   }

   retval = poll(poll_fds, (nfds_t)poll_fd_count, timeout_msecs);
   if (retval > 0)
   {
      poll_fd_count = 0;
      for (i = 0; i < attempt_count; i++)
      {
         if (attempts[i].pending)
         {
            /*
             * Any event means the attempt completed, whether or not
             * it succeeded is determined through SO_ERROR by the caller.
             */
            if (poll_fds[poll_fd_count].revents != 0)
            {
               attempts[i].ready = 1;
               ready_count++;
            }
            poll_fd_count++;
         }
      }
   }
#else
   fd_set wfds;
   fd_set efds;
   struct timeval timeout;
   jb_socket max_fd = 0;

   /*
    * A completed attempt makes the socket writable, except on
    * Windows where a failed attempt is reported through the
    * exception set instead.
    */
   FD_ZERO(&wfds);
   FD_ZERO(&efds);
   for (i = 0; i < attempt_count; i++)
   {
      attempts[i].ready = 0;
      if (attempts[i].pending)
      {
         FD_SET(attempts[i].fd, &wfds);
         FD_SET(attempts[i].fd, &efds);
         if (attempts[i].fd > max_fd)
         {
            max_fd = attempts[i].fd;
         }
      }
   }

   timeout.tv_sec  = timeout_msecs / 1000;
   timeout.tv_usec = (timeout_msecs % 1000) * 1000;

   /* MS Windows uses int, not SOCKET, for the 1st arg of select(). Weird! */
   retval = select((int)max_fd + 1, NULL, &wfds, &efds, &timeout);
   if (retval > 0)
   {
      for (i = 0; i < attempt_count; i++)
      {
         if (attempts[i].pending
            && (FD_ISSET(attempts[i].fd, &wfds) || FD_ISSET(attempts[i].fd, &efds)))
         {
            attempts[i].ready = 1;
            ready_count++;
         }
      }
   }
#endif /* def HAVE_POLL */

   if (retval < 0)
   {
      return -1;
   }

   return ready_count;
}


/*********************************************************************
 *
 * Function    :  rfc2553_connect_to
 *
 * Description :  Resolves the host and connects to one of its
 *                addresses using getaddrinfo().
 *
 *                Implements the connection part of Happy Eyeballs
 *                (RFC 8305): the first connection attempt is started
 *                right away, additional attempts to the remaining
 *                addresses are started as soon as a previous attempt
 *                failed or the connect-attempt-delay expired while
 *                previous attempts are still pending. The first
 *                attempt to succeed wins and the others are aborted.
 *
 *                As getaddrinfo() is synchronous and returns the
 *                addresses of all families at once, the "Resolution
 *                Delay" part of RFC 8305 doesn't apply.
 *
 * Parameters  :
 *          1  :  host = hostname to connect to
 *          2  :  portnum = port to connect to
 *          3  :  csp = Current client state (buffers, headers, etc...)
 *
 * Returns     :  JB_INVALID_SOCKET => failure, else it is the socket
 *                file descriptor.
 *
 *********************************************************************/
static jb_socket rfc2553_connect_to(const char *host, int portnum, struct client_state *csp)
{
   struct addrinfo hints;
   struct addrinfo *result;
   const struct addrinfo *rp;
   struct connect_attempt *attempts;
   struct connect_attempt *attempt;
   const struct connect_attempt *last_attempt = NULL;
   const struct connect_attempt *failed_attempt = NULL;
   struct connect_attempt *winner = NULL;
   struct pollfd *poll_fds = NULL;
   const int connect_attempt_delay = csp->config->connect_attempt_delay;
   char service[6];
   char error_buffer[SOCKET_STRERROR_BUFFER_SIZE];
   int retval;
   jb_socket fd = JB_INVALID_SOCKET;
   int address_count = 0;
   int attempt_count = 0;
   int pending_count = 0;
   int start_next_attempt = 1;
   long timeout_msecs;
   long remaining_msecs;
   int i;
   /*
    * XXX: Initializing it here is only necessary
    *      because not all situations are properly
    *      covered yet.
    */
   int socket_error = 0;

   /* Don't leak memory when retrying. */
   freez(csp->error_message);
   freez(csp->http->host_ip_addr_str);

   retval = snprintf(service, sizeof(service), "%d", portnum);
   if ((-1 == retval) || (sizeof(service) <= retval))
   {
      log_error(LOG_LEVEL_ERROR,
         "Port number (%d) ASCII decimal representation doesn't fit into 6 bytes",
         portnum);
      csp->error_message = strdup("Invalid port number");
      csp->http->host_ip_addr_str = strdup("unknown");
      return(JB_INVALID_SOCKET);
   }

   memset((char *)&hints, 0, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = AI_NUMERICSERV; /* avoid service look-up */
#ifdef AI_ADDRCONFIG
   hints.ai_flags |= AI_ADDRCONFIG;
#endif
   if ((retval = getaddrinfo(host, service, &hints, &result)))
   {
      log_error(LOG_LEVEL_INFO,
         "Can not resolve %s: %s", host, gai_strerror(retval));
      csp->error_message = strdup(gai_strerror(retval));
      csp->http->host_ip_addr_str = strdup("unknown");
      /* XXX: Should find a better way to propagate this error. */
      errno = EINVAL;
      return(JB_INVALID_SOCKET);
   }

   csp->http->host_ip_addr_str = zalloc_or_die(NI_MAXHOST);

   /*
    * Cap the number of addresses to the capacity of select()'s fd_sets
    * for the unlikely event we get more addresses than the capacity
    * (64 on Windows, typically 1024 or more on POSIX).
    */
   for (rp = result; (rp != NULL) && (address_count < FD_SETSIZE);
      rp = rp->ai_next)
   {
      address_count++;
   }
   attempts = zalloc_or_die((size_t)address_count * sizeof(*attempts));
#ifdef HAVE_POLL
   poll_fds = zalloc_or_die((size_t)address_count * sizeof(*poll_fds));
#endif
   order_addresses(result, attempts, address_count);
   for (i = 0; i < address_count; i++)
   {
      attempts[i].fd = JB_INVALID_SOCKET;
   }

   while ((fd == JB_INVALID_SOCKET)
      && ((pending_count > 0) || (attempt_count < address_count)))
   {
      /*
       * Start the next attempt if there's nothing else to wait for,
       * a previous attempt just failed or the connect-attempt-delay
       * expired since the last attempt was started.
       */
      if ((attempt_count < address_count)
         && (start_next_attempt || (pending_count == 0)
            || ((connect_attempt_delay > 0)
               && (msecs_since(&last_attempt->start_time)
                  >= connect_attempt_delay))))
      {
         attempt = &attempts[attempt_count++];
         last_attempt = attempt;
         start_next_attempt = 0;

         switch (start_connection_attempt(csp, attempt, &socket_error))
         {
            case CONNECT_ATTEMPT_CONNECTED:
               fd = attempt->fd;
               winner = attempt;
               break;
            case CONNECT_ATTEMPT_PENDING:
               if (pending_count > 0)
               {
                  log_error(LOG_LEVEL_CONNECT,
                     "Connecting to %s[%s]:%s while %d earlier "
                     "connection attempt(s) are still pending.",
                     host, attempt->ip_addr_str, service, pending_count);
               }
               attempt->pending = 1;
               pending_count++;
               break;
            case CONNECT_ATTEMPT_FAILED:
            default:
               failed_attempt = attempt;
               if ((pending_count > 0) || (attempt_count < address_count))
               {
                  /*
                   * Log this now as we'll try another address next.
                   * If the last address fails, too, it will get logged
                   * outside the loop body.
                   */
                  log_error(LOG_LEVEL_CONNECT,
                     "Could not connect to %s[%s]:%s: %s.",
                     host, attempt->ip_addr_str, service,
                     socket_strerror(socket_error,
                        error_buffer, sizeof(error_buffer)));
               }
               start_next_attempt = 1;
               break;
         }
         continue;
      }

      /*
       * Wait for the pending attempts until one of them completes,
       * the oldest one times out or it's time to start another one.
       */
      timeout_msecs = CONNECT_TIMEOUT_MSECS;
      for (i = 0; i < attempt_count; i++)
      {
         if (attempts[i].pending)
         {
            remaining_msecs = CONNECT_TIMEOUT_MSECS
               - msecs_since(&attempts[i].start_time);
            if (remaining_msecs < timeout_msecs)
            {
               timeout_msecs = remaining_msecs;
            }
         }
      }
      if ((connect_attempt_delay > 0) && (attempt_count < address_count))
      {
         remaining_msecs = connect_attempt_delay
            - msecs_since(&last_attempt->start_time);
         if (remaining_msecs < timeout_msecs)
         {
            timeout_msecs = remaining_msecs;
         }
      }
      if (timeout_msecs < 0)
      {
         timeout_msecs = 0;
      }

      retval = wait_for_connection_attempts(attempts, attempt_count,
         (int)timeout_msecs, poll_fds);
      if (retval < 0)
      {
         socket_error = get_socket_error();
         if (socket_error == EINTR)
         {
            continue;
         }
         log_error(LOG_LEVEL_ERROR, "Waiting for the connection "
            "attempts to %s to complete failed: %E", host);
         break;
      }

      /* Check which of the pending attempts completed or timed out */
      for (i = 0; i < attempt_count; i++)
      {
         attempt = &attempts[i];
         if (!attempt->pending)
         {
            continue;
         }

         if (attempt->ready)
         {
            int connection_error = 0;
            socklen_t optlen = sizeof(connection_error);

            if (getsockopt(attempt->fd, SOL_SOCKET, SO_ERROR,
                  (char *)&connection_error, &optlen))
            {
               connection_error = get_socket_error();
               log_error(LOG_LEVEL_ERROR, "Could not get the state of "
                  "the connection to %s[%s]:%s: %s; dropping connection.",
                  host, attempt->ip_addr_str, service,
                  socket_strerror(connection_error,
                     error_buffer, sizeof(error_buffer)));
            }
            if (!connection_error)
            {
               /* Connection established, no need to wait for the others. */
               fd = attempt->fd;
               winner = attempt;
               break;
            }
            socket_error = connection_error;
         }
         else if (msecs_since(&attempt->start_time) >= CONNECT_TIMEOUT_MSECS)
         {
#ifdef _WIN32
            socket_error = WSAETIMEDOUT;
#else
            socket_error = ETIMEDOUT;
#endif
         }
         else
         {
            /* Still pending */
            continue;
         }
         failed_attempt = attempt;

         if ((pending_count > 1) || (attempt_count < address_count))
         {
            /*
             * There's another address we can try, so log that this
             * one didn't work out. If the last one fails, too,
             * it will get logged outside the loop body so we don't
             * have to mention it here.
             */
            log_error(LOG_LEVEL_CONNECT, "Could not connect to %s[%s]:%s: %s.",
               host, attempt->ip_addr_str, service,
               socket_strerror(socket_error, error_buffer, sizeof(error_buffer)));
         }
         close_socket(attempt->fd);
         attempt->fd = JB_INVALID_SOCKET;
         attempt->pending = 0;
         pending_count--;
         start_next_attempt = 1;
      }
   }

   /* Abort the attempts that didn't win. */
   for (i = 0; i < attempt_count; i++)
   {
      if ((attempts[i].fd != JB_INVALID_SOCKET) && (attempts[i].fd != fd))
      {
         log_error(LOG_LEVEL_CONNECT,
            "Aborting the connection attempt to %s[%s]:%s.",
            host, attempts[i].ip_addr_str, service);
         close_socket(attempts[i].fd);
      }
   }
   freeaddrinfo(result);
   freez(poll_fds);

   if (winner == NULL)
   {
      if (failed_attempt != NULL)
      {
         strlcpy(csp->http->host_ip_addr_str,
            failed_attempt->ip_addr_str, NI_MAXHOST);
      }
      freez(attempts);
      log_error(LOG_LEVEL_CONNECT, "Could not connect to %s[%s]:%s: %s.",
         host, csp->http->host_ip_addr_str, service,
         socket_strerror(socket_error, error_buffer, sizeof(error_buffer)));
      csp->error_message = strdup(socket_strerror(socket_error,
         error_buffer, sizeof(error_buffer)));
      return(JB_INVALID_SOCKET);
   }

   set_socket_blocking_mode(winner, TRUE);
   strlcpy(csp->http->host_ip_addr_str, winner->ip_addr_str, NI_MAXHOST);
   freez(attempts);

   log_error(LOG_LEVEL_CONNECT, "Connected to %s[%s]:%s.",
      host, csp->http->host_ip_addr_str, service);

   return(fd);

}

#else /* ndef HAVE_RFC2553 */
/* Pre-getaddrinfo implementation */

static jb_socket no_rfc2553_connect_to(const char *host, int portnum, struct client_state *csp)
{
   struct sockaddr_in inaddr;
   jb_socket fd;
   unsigned int addr;
#ifdef HAVE_POLL
   struct pollfd poll_fd[1];
#else
   fd_set wfds;
   struct timeval tv[1];
#endif
#if !defined(_WIN32) && !defined(__BEOS__)
   int   flags;
#endif

#ifdef FEATURE_ACL
   struct access_control_addr dst[1];
#endif /* def FEATURE_ACL */

   /* Don't leak memory when retrying. */
   freez(csp->http->host_ip_addr_str);

   memset((char *)&inaddr, 0, sizeof inaddr);

   if ((addr = resolve_hostname_to_ip(host)) == INADDR_NONE)
   {
      csp->http->host_ip_addr_str = strdup("unknown");
      return(JB_INVALID_SOCKET);
   }

#ifdef FEATURE_ACL
   dst->addr = ntohl(addr);
   dst->port = portnum;

   if (block_acl(csp, dst))
   {
      errno = EPERM;
      return(JB_INVALID_SOCKET);
   }
#endif /* def FEATURE_ACL */

   inaddr.sin_addr.s_addr = addr;
   inaddr.sin_family      = AF_INET;
   csp->http->host_ip_addr_str = strdup(inet_ntoa(inaddr.sin_addr));

#ifndef _WIN32
   if (sizeof(inaddr.sin_port) == sizeof(short))
#endif /* ndef _WIN32 */
   {
      inaddr.sin_port = htons((unsigned short) portnum);
   }
#ifndef _WIN32
   else
   {
      inaddr.sin_port = htonl((unsigned long)portnum);
   }
#endif /* ndef _WIN32 */

   fd = socket(inaddr.sin_family, SOCK_STREAM, 0);
#ifdef _WIN32
   if (fd == JB_INVALID_SOCKET)
#else
   if (fd < 0)
#endif
   {
      return(JB_INVALID_SOCKET);
   }

#ifndef HAVE_POLL
#ifndef _WIN32
   if (fd >= FD_SETSIZE)
   {
      log_error(LOG_LEVEL_ERROR,
         "Server socket number too high to use select(): %d >= %d",
         fd, FD_SETSIZE);
      close_socket(fd);
      return JB_INVALID_SOCKET;
   }
#endif
#endif

   set_no_delay_flag(fd);

#if !defined(_WIN32) && !defined(__BEOS__)
   if ((flags = fcntl(fd, F_GETFL, 0)) != -1)
   {
      flags |= O_NDELAY;
      fcntl(fd, F_SETFL, flags);
#ifdef FEATURE_EXTERNAL_FILTERS
      mark_socket_for_close_on_execute(fd);
#endif
   }
#endif /* !defined(_WIN32) && !defined(__BEOS__) */

   while (connect(fd, (struct sockaddr *) & inaddr, sizeof inaddr) == JB_INVALID_SOCKET)
   {
#ifdef _WIN32
      if (errno == WSAEINPROGRESS)
#else /* ifndef _WIN32 */
      if (errno == EINPROGRESS)
#endif /* ndef _WIN32 */
      {
         break;
      }

      if (errno != EINTR)
      {
         close_socket(fd);
         return(JB_INVALID_SOCKET);
      }
   }

#if !defined(_WIN32) && !defined(__BEOS__)
   if (flags != -1)
   {
      flags &= ~O_NDELAY;
      fcntl(fd, F_SETFL, flags);
   }
#endif /* !defined(_WIN32) && !defined(__BEOS__) */

#ifdef HAVE_POLL
   poll_fd[0].fd = fd;
   poll_fd[0].events = POLLOUT;

   if (poll(poll_fd, 1, 30000) <= 0)
#else
   /* wait for connection to complete */
   FD_ZERO(&wfds);
   FD_SET(fd, &wfds);

   tv->tv_sec  = 30;
   tv->tv_usec = 0;

   /* MS Windows uses int, not SOCKET, for the 1st arg of select(). Weird! */
   if (select((int)fd + 1, NULL, &wfds, NULL, tv) <= 0)
#endif
   {
      close_socket(fd);
      return(JB_INVALID_SOCKET);
   }
   return(fd);

}
#endif /* ndef HAVE_RFC2553 */


/*********************************************************************
 *
 * Function    :  write_socket
 *
 * Description :  Write the contents of buf (for n bytes) to socket fd.
 *
 * Parameters  :
 *          1  :  fd = file descriptor (aka. handle) of socket to write to.
 *          2  :  buf = pointer to data to be written.
 *          3  :  len = length of data to be written to the socket "fd".
 *
 * Returns     :  0 on success (entire buffer sent).
 *                nonzero on error.
 *
 *********************************************************************/
int write_socket(jb_socket fd, const char *buf, size_t len)
{
   if (len == 0)
   {
      return 0;
   }

#ifdef FUZZ
   if (!daemon_mode && fd <= 3)
   {
      log_error(LOG_LEVEL_WRITING, "Pretending to write to socket %d: %N", fd, len, buf);
      return 0;
   }
#endif

   log_error(LOG_LEVEL_WRITING, "to socket %d: %N", fd, len, buf);

#if defined(_WIN32)
   return (send(fd, buf, (int)len, 0) != (int)len);
#elif defined(__BEOS__)
   return (send(fd, buf, len, 0) != len);
#else
   return (write(fd, buf, len) != len);
#endif

}


/*********************************************************************
 *
 * Function    :  write_socket_delayed
 *
 * Description :  Write the contents of buf (for n bytes) to
 *                socket fd, optionally delaying the operation.
 *
 * Parameters  :
 *          1  :  fd = File descriptor (aka. handle) of socket to write to.
 *          2  :  buf = Pointer to data to be written.
 *          3  :  len = Length of data to be written to the socket "fd".
 *          4  :  delay = Delay in milliseconds.
 *
 * Returns     :  0 on success (entire buffer sent).
 *                nonzero on error.
 *
 *********************************************************************/
int write_socket_delayed(jb_socket fd, const char *buf, size_t len, unsigned int delay)
{
   size_t i = 0;

   if (delay == 0)
   {
      return write_socket(fd, buf, len);
   }

   while (i < len)
   {
      size_t write_length;
      enum {MAX_WRITE_LENGTH = 10};

      if ((i + MAX_WRITE_LENGTH) > len)
      {
         write_length = len - i;
      }
      else
      {
         write_length = MAX_WRITE_LENGTH;
      }

      privoxy_millisleep(delay);

      if (write_socket(fd, buf + i, write_length) != 0)
      {
         return 1;
      }
      i += write_length;
   }

   return 0;

}


/*********************************************************************
 *
 * Function    :  read_socket
 *
 * Description :  Read from a TCP/IP socket in a platform independent way.
 *
 * Parameters  :
 *          1  :  fd = file descriptor of the socket to read
 *          2  :  buf = pointer to buffer where data will be written
 *                Must be >= len bytes long.
 *          3  :  len = maximum number of bytes to read
 *
 * Returns     :  On success, the number of bytes read is returned (zero
 *                indicates end of file), and the file position is advanced
 *                by this number.  It is not an error if this number is
 *                smaller than the number of bytes requested; this may hap-
 *                pen for example because fewer bytes are actually available
 *                right now (maybe because we were close to end-of-file, or
 *                because we are reading from a pipe, or from a terminal,
 *                or because read() was interrupted by a signal).  On error,
 *                -1 is returned, and errno is set appropriately.  In this
 *                case it is left unspecified whether the file position (if
 *                any) changes.
 *
 *********************************************************************/
int read_socket(jb_socket fd, char *buf, int len)
{
   int ret;

   if (len <= 0)
   {
      return(0);
   }

#if defined(_WIN32)
   ret = recv(fd, buf, len, 0);
#elif defined(__BEOS__)
   ret = recv(fd, buf, (size_t)len, 0);
#else
   ret = (int)read(fd, buf, (size_t)len);
#endif

   if (ret > 0)
   {
      log_error(LOG_LEVEL_RECEIVED, "from socket %d: %N", fd, ret, buf);
   }

   return ret;
}


/*********************************************************************
 *
 * Function    :  data_is_available
 *
 * Description :  Waits for data to arrive on a socket.
 *
 * Parameters  :
 *          1  :  fd = file descriptor of the socket to read
 *          2  :  seconds_to_wait = number of seconds after which we give up.
 *
 * Returns     :  TRUE if data arrived in time,
 *                FALSE otherwise.
 *
 *********************************************************************/
int data_is_available(jb_socket fd, int seconds_to_wait)
{
   int n;
   char buf[10];
#ifdef HAVE_POLL
   struct pollfd poll_fd[1];

   poll_fd[0].fd = fd;
   poll_fd[0].events = POLLIN;

   n = poll(poll_fd, 1, seconds_to_wait * 1000);
#else
   fd_set rfds;
   struct timeval timeout;

   memset(&timeout, 0, sizeof(timeout));
   timeout.tv_sec = seconds_to_wait;

   FD_ZERO(&rfds);
   FD_SET(fd, &rfds);

   n = select(fd+1, &rfds, NULL, NULL, &timeout);
#endif

   /*
    * XXX: Do we care about the different error conditions?
    */
   return ((n == 1) && (1 == recv(fd, buf, 1, MSG_PEEK)));
}


/*********************************************************************
 *
 * Function    :  close_socket
 *
 * Description :  Closes a TCP/IP socket
 *
 * Parameters  :
 *          1  :  fd = file descriptor of socket to be closed
 *
 * Returns     :  void
 *
 *********************************************************************/
void close_socket(jb_socket fd)
{
#if defined(_WIN32) || defined(__BEOS__)
   closesocket(fd);
#else
   close(fd);
#endif
}


/*********************************************************************
 *
 * Function    :  drain_and_close_socket
 *
 * Description :  Closes a TCP/IP socket after draining unread data
 *
 * Parameters  :
 *          1  :  fd = file descriptor of the socket to be closed
 *
 * Returns     :  void
 *
 *********************************************************************/
void drain_and_close_socket(jb_socket fd)
{
#ifdef FEATURE_CONNECTION_KEEP_ALIVE
   if (socket_is_still_alive(fd))
#endif
   {
      int bytes_drained_total = 0;
      int bytes_drained;

#ifdef HAVE_SHUTDOWN
/* Apparently Windows has shutdown() but not SHUT_WR. */
#ifndef SHUT_WR
#define SHUT_WR 1
#endif
      if (0 != shutdown(fd, SHUT_WR))
      {
         log_error(LOG_LEVEL_CONNECT, "Failed to shutdown socket %d: %E", fd);
      }
#endif
#define ARBITRARY_DRAIN_LIMIT 10000
      do
      {
         char drainage[500];

         if (!data_is_available(fd, 0))
         {
            /*
             * If there is no data available right now, don't try
             * to drain the socket as read_socket() could block.
             */
            break;
         }

         bytes_drained = read_socket(fd, drainage, sizeof(drainage));
         if (bytes_drained < 0)
         {
            log_error(LOG_LEVEL_CONNECT, "Failed to drain socket %d: %E", fd);
         }
         else if (bytes_drained > 0)
         {
            bytes_drained_total += bytes_drained;
            if (bytes_drained_total > ARBITRARY_DRAIN_LIMIT)
            {
               log_error(LOG_LEVEL_CONNECT, "Giving up draining socket %d.", fd);
               break;
            }
         }
      } while (bytes_drained > 0);
      if (bytes_drained_total != 0)
      {
         log_error(LOG_LEVEL_CONNECT,
            "Drained %d bytes before closing socket %d.", bytes_drained_total, fd);
      }
   }

   close_socket(fd);

}


/*********************************************************************
 *
 * Function    :  bind_port
 *
 * Description :  Call socket, set socket options, and listen.
 *                Called by listen_loop to "boot up" our proxy address.
 *
 * Parameters  :
 *          1  :  hostnam = TCP/IP address to bind/listen to
 *          2  :  portnum = port to listen on
 *          3  :  backlog = Listen backlog
 *          4  :  pfd = pointer used to return file descriptor.
 *
 * Returns     :  if success, returns 0 and sets *pfd.
 *                if failure, returns -3 if address is in use,
 *                                    -2 if address unresolvable,
 *                                    -1 otherwise
 *********************************************************************/
int bind_port(const char *hostnam, int portnum, int backlog, jb_socket *pfd)
{
#ifdef HAVE_RFC2553
   struct addrinfo hints;
   struct addrinfo *result, *rp;
   /*
    * XXX: portnum should be a string to allow symbolic service
    * names in the configuration file and to avoid the following
    * int2string.
    */
   char servnam[6];
   int retval;
#else
   struct sockaddr_in inaddr;
#endif /* def HAVE_RFC2553 */
   jb_socket fd;
#ifndef _WIN32
   int one = 1;
#endif /* ndef _WIN32 */

   *pfd = JB_INVALID_SOCKET;

#ifdef HAVE_RFC2553
   retval = snprintf(servnam, sizeof(servnam), "%d", portnum);
   if ((-1 == retval) || (sizeof(servnam) <= retval))
   {
      log_error(LOG_LEVEL_ERROR,
         "Port number (%d) ASCII decimal representation doesn't fit into 6 bytes.",
         portnum);
      return -1;
   }

   memset(&hints, 0, sizeof(struct addrinfo));
   if (hostnam == NULL)
   {
      /*
       * XXX: This is a hack. The right thing to do
       * would be to bind to both AF_INET and AF_INET6.
       * This will also fail if there is no AF_INET
       * version available.
       */
      hints.ai_family = AF_INET;
   }
   else
   {
      hints.ai_family = AF_UNSPEC;
   }
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = AI_PASSIVE;
   hints.ai_protocol = 0; /* Really any stream protocol or TCP only */
   hints.ai_canonname = NULL;
   hints.ai_addr = NULL;
   hints.ai_next = NULL;

   if ((retval = getaddrinfo(hostnam, servnam, &hints, &result)))
   {
      log_error(LOG_LEVEL_ERROR,
         "Can not resolve %s: %s", hostnam, gai_strerror(retval));
      return -2;
   }
#else
   memset((char *)&inaddr, '\0', sizeof inaddr);

   inaddr.sin_family      = AF_INET;
   inaddr.sin_addr.s_addr = resolve_hostname_to_ip(hostnam);

   if (inaddr.sin_addr.s_addr == INADDR_NONE)
   {
      return(-2);
   }

#ifndef _WIN32
   if (sizeof(inaddr.sin_port) == sizeof(short))
#endif /* ndef _WIN32 */
   {
      inaddr.sin_port = htons((unsigned short) portnum);
   }
#ifndef _WIN32
   else
   {
      inaddr.sin_port = htonl((unsigned long) portnum);
   }
#endif /* ndef _WIN32 */
#endif /* def HAVE_RFC2553 */

#ifdef HAVE_RFC2553
   for (rp = result; rp != NULL; rp = rp->ai_next)
   {
      fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
#else
   fd = socket(AF_INET, SOCK_STREAM, 0);
#endif /* def HAVE_RFC2553 */

#ifdef _WIN32
   if (fd == JB_INVALID_SOCKET)
#else
   if (fd < 0)
#endif
   {
#ifdef HAVE_RFC2553
      continue;
#else
      return(-1);
#endif
   }

#ifdef FEATURE_EXTERNAL_FILTERS
   mark_socket_for_close_on_execute(fd);
#endif

#ifndef _WIN32
   /*
    * This is not needed for Win32 - in fact, it stops
    * duplicate instances of Privoxy from being caught.
    *
    * On UNIX, we assume the user is sensible enough not
    * to start Privoxy multiple times on the same IP.
    * Without this, stopping and restarting Privoxy
    * from a script fails.
    * Note: SO_REUSEADDR is meant to only take over
    * sockets which are *not* in listen state in Linux,
    * e.g. sockets in TIME_WAIT. YMMV.
    */
   setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
#endif /* ndef _WIN32 */

#ifdef IP_FREEBIND
   setsockopt(fd, IPPROTO_IP, IP_FREEBIND, (char *)&one, sizeof(one));
#endif

#ifdef HAVE_RFC2553
   if (bind(fd, rp->ai_addr, rp->ai_addrlen) < 0)
#else
   if (bind(fd, (struct sockaddr *)&inaddr, sizeof(inaddr)) < 0)
#endif
   {
#ifdef _WIN32
      errno = WSAGetLastError();
      if (errno == WSAEADDRINUSE)
#else
      if (errno == EADDRINUSE)
#endif
      {
#ifdef HAVE_RFC2553
         freeaddrinfo(result);
#endif
         close_socket(fd);
         return(-3);
      }
      else
      {
         close_socket(fd);
#ifndef HAVE_RFC2553
         return(-1);
      }
   }
#else
      }
   }
   else
   {
      /* bind() succeeded, escape from for-loop */
      /*
       * XXX: Support multiple listening sockets (e.g. localhost
       * resolves to AF_INET and AF_INET6, but only the first address
       * is used
       */
      break;
   }
   }

   freeaddrinfo(result);
   if (rp == NULL)
   {
      /* All bind()s failed */
      return(-1);
   }
#endif /* ndef HAVE_RFC2553 */

   while (listen(fd, backlog) == -1)
   {
      if (errno != EINTR)
      {
         close_socket(fd);
         return(-1);
      }
   }

   *pfd = fd;
   return 0;

}


/*********************************************************************
 *
 * Function    :  get_host_information
 *
 * Description :  Determines the IP address the client used to
 *                reach us, the hostname associated with it and
 *                the listening address and port.
 *
 *                XXX: Most of the code has been copy and pasted
 *                from accept_connection() and not all of the
 *                ifdefs paths have been tested afterwards.
 *
 * Parameters  :
 *          1  :  afd = File descriptor returned from accept().
 *          2  :  ip_address = Pointer to return the pointer to
 *                             the ip address string.
 *          3  :  port =       Pointer to return the pointer to
 *                             the TCP port string.
 *          4  :  hostname =   Pointer to return the pointer to
 *                             the hostname or NULL if the caller
 *                             isn't interested in it.
 *
 * Returns     :  void.
 *
 *********************************************************************/
void get_host_information(jb_socket afd, char **ip_address, char **port,
                          char **hostname)
{
#ifdef HAVE_RFC2553
   struct sockaddr_storage server;
   int retval;
#else
   struct sockaddr_in server;
   struct hostent *host = NULL;
#endif /* HAVE_RFC2553 */
#if defined(_WIN32)
   /* according to accept_connection() this fixes a warning. */
   int s_length, s_length_provided;
#else
   socklen_t s_length, s_length_provided;
#endif
#ifndef HAVE_RFC2553
#if defined(HAVE_GETHOSTBYADDR_R_8_ARGS) ||  defined(HAVE_GETHOSTBYADDR_R_7_ARGS) || defined(HAVE_GETHOSTBYADDR_R_5_ARGS)
   struct hostent result;
#if defined(HAVE_GETHOSTBYADDR_R_5_ARGS)
   struct hostent_data hdata;
#else
   char hbuf[HOSTENT_BUFFER_SIZE];
   int thd_err;
#endif /* def HAVE_GETHOSTBYADDR_R_5_ARGS */
#endif /* def HAVE_GETHOSTBYADDR_R_(8|7|5)_ARGS */
#endif /* ifndef HAVE_RFC2553 */
   s_length = s_length_provided = sizeof(server);

   if (NULL != hostname)
   {
      *hostname = NULL;
   }
   *ip_address = NULL;
   *port = NULL;

   if (!getsockname(afd, (struct sockaddr *) &server, &s_length))
   {
      if (s_length > s_length_provided)
      {
         log_error(LOG_LEVEL_ERROR, "getsockname() truncated server address");
         return;
      }
/*
 * XXX: Workaround for missing header on Windows when
 *      configured with --disable-ipv6-support.
 *      The proper fix is to not use NI_MAXSERV in
 *      that case. It works by accident on other platforms
 *      as <netdb.h> is included unconditionally there.
 */
#ifndef NI_MAXSERV
#define NI_MAXSERV 32
#endif
      *port = malloc_or_die(NI_MAXSERV);

#ifdef HAVE_RFC2553
      *ip_address = malloc_or_die(NI_MAXHOST);
      retval = getnameinfo((struct sockaddr *) &server, s_length,
         *ip_address, NI_MAXHOST, *port, NI_MAXSERV,
         NI_NUMERICHOST|NI_NUMERICSERV);
      if (retval)
      {
         log_error(LOG_LEVEL_ERROR,
            "Unable to print my own IP address: %s", gai_strerror(retval));
         freez(*ip_address);
         freez(*port);
         return;
      }
#else
      *ip_address = strdup(inet_ntoa(server.sin_addr));
      snprintf(*port, NI_MAXSERV, "%hu", ntohs(server.sin_port));
#endif /* HAVE_RFC2553 */
      if (NULL == hostname)
      {
         /*
          * We're done here, the caller isn't
          * interested in knowing the hostname.
          */
         return;
      }

#ifdef HAVE_RFC2553
      *hostname = malloc_or_die(NI_MAXHOST);
      retval = getnameinfo((struct sockaddr *) &server, s_length,
         *hostname, NI_MAXHOST, NULL, 0, NI_NAMEREQD);
      if (retval)
      {
         log_error(LOG_LEVEL_ERROR,
            "Unable to resolve my own IP address: %s", gai_strerror(retval));
         freez(*hostname);
      }
#else
#if defined(HAVE_GETHOSTBYADDR_R_8_ARGS)
      gethostbyaddr_r((const char *)&server.sin_addr,
                      sizeof(server.sin_addr), AF_INET,
                      &result, hbuf, HOSTENT_BUFFER_SIZE,
                      &host, &thd_err);
#elif defined(HAVE_GETHOSTBYADDR_R_7_ARGS)
      host = gethostbyaddr_r((const char *)&server.sin_addr,
                      sizeof(server.sin_addr), AF_INET,
                      &result, hbuf, HOSTENT_BUFFER_SIZE, &thd_err);
#elif defined(HAVE_GETHOSTBYADDR_R_5_ARGS)
      if (0 == gethostbyaddr_r((const char *)&server.sin_addr,
                               sizeof(server.sin_addr), AF_INET,
                               &result, &hdata))
      {
         host = &result;
      }
      else
      {
         host = NULL;
      }
#elif defined(MUTEX_LOCKS_AVAILABLE)
      privoxy_mutex_lock(&resolver_mutex);
      host = gethostbyaddr((const char *)&server.sin_addr,
                           sizeof(server.sin_addr), AF_INET);
      privoxy_mutex_unlock(&resolver_mutex);
#else
      host = gethostbyaddr((const char *)&server.sin_addr,
                           sizeof(server.sin_addr), AF_INET);
#endif
      if (host == NULL)
      {
         log_error(LOG_LEVEL_ERROR, "Unable to get my own hostname: %E\n");
      }
      else
      {
         *hostname = strdup(host->h_name);
      }
#endif /* else def HAVE_RFC2553 */
   }

   return;
}


/*********************************************************************
 *
 * Function    :  accept_connection
 *
 * Description :  Accepts a connection on one of possibly multiple
 *                sockets. The socket(s) to check must have been
 *                created using bind_port().
 *
 * Parameters  :
 *          1  :  csp = Client state, cfd, ip_addr_str, and
 *                      ip_addr_long will be set by this routine.
 *          2  :  fds = File descriptors returned from bind_port
 *
 * Returns     :  when a connection is accepted, it returns 1 (TRUE).
 *                On an error it returns 0 (FALSE).
 *
 *********************************************************************/
int accept_connection(struct client_state * csp, jb_socket fds[])
{
#ifdef HAVE_RFC2553
   /* XXX: client is stored directly into csp->tcp_addr */
#define client (csp->tcp_addr)
#else
   struct sockaddr_in client;
#endif
   jb_socket afd;
#if defined(_WIN32)
   /* Weirdness - fix a warning. */
   int c_length;
#else
   socklen_t c_length;
#endif
   int retval;
   int i;
   int max_selected_socket;
#ifdef HAVE_POLL
   struct pollfd poll_fds[MAX_LISTENING_SOCKETS];
   nfds_t polled_sockets;
#else
   fd_set selected_fds;
#endif
   jb_socket fd;
   const char *host_addr;
   size_t listen_addr_size;

   c_length = sizeof(client);

#ifdef HAVE_POLL
   memset(poll_fds, 0, sizeof(poll_fds));
   polled_sockets = 0;
#else
   /*
    * Wait for a connection on any socket.
    * Return immediately if no socket is listening.
    * XXX: Why not treat this as fatal error?
    */
   FD_ZERO(&selected_fds);
#endif
   max_selected_socket = 0;
   for (i = 0; i < MAX_LISTENING_SOCKETS; i++)
   {
      if (JB_INVALID_SOCKET != fds[i])
      {
#ifdef HAVE_POLL
         poll_fds[i].fd = fds[i];
         poll_fds[i].events = POLLIN;
         polled_sockets++;
#else
         FD_SET(fds[i], &selected_fds);
#endif
         if (max_selected_socket < fds[i] + 1)
         {
            max_selected_socket = fds[i] + 1;
         }
      }
   }
   if (0 == max_selected_socket)
   {
      return 0;
   }
   do
   {
#ifdef HAVE_POLL
      retval = poll(poll_fds, polled_sockets, -1);
#else
      retval = select(max_selected_socket, &selected_fds, NULL, NULL, NULL);
#endif
   } while (retval < 0 && errno == EINTR);
   if (retval <= 0)
   {
      if (0 == retval)
      {
         log_error(LOG_LEVEL_ERROR,
            "Waiting on new client failed because select(2) returned 0."
            " This should not happen.");
      }
      else
      {
         log_error(LOG_LEVEL_ERROR,
            "Waiting on new client failed because of problems in select(2): "
            "%s.", strerror(errno));
      }
      return 0;
   }
#ifdef HAVE_POLL
   for (i = 0; i < MAX_LISTENING_SOCKETS && (poll_fds[i].revents == 0); i++);
#else
   for (i = 0; i < MAX_LISTENING_SOCKETS && !FD_ISSET(fds[i], &selected_fds);
         i++);
#endif
   if (i >= MAX_LISTENING_SOCKETS)
   {
      log_error(LOG_LEVEL_ERROR,
         "select(2) reported connected clients (number = %u, "
         "descriptor boundary = %u), but none found.",
         retval, max_selected_socket);
      return 0;
   }
   fd = fds[i];

   /* Accept selected connection */
#ifdef _WIN32
   afd = accept (fd, (struct sockaddr *) &client, &c_length);
   if (afd == JB_INVALID_SOCKET)
   {
      return 0;
   }
#else
   do
   {
      afd = accept (fd, (struct sockaddr *) &client, &c_length);
   } while (afd < 0 && errno == EINTR);
   if (afd < 0)
   {
      return 0;
   }
#endif

#ifdef SO_LINGER
   {
      struct linger linger_options;
      linger_options.l_onoff  = 1;
      linger_options.l_linger = 5;
      if (0 != setsockopt(afd, SOL_SOCKET, SO_LINGER, &linger_options, sizeof(linger_options)))
      {
         log_error(LOG_LEVEL_ERROR, "Setting SO_LINGER on socket %d failed.", afd);
      }
   }
#endif

#ifndef HAVE_POLL
#ifndef _WIN32
   if (afd >= FD_SETSIZE)
   {
      log_error(LOG_LEVEL_ERROR,
         "Client socket number too high to use select(): %d >= %d",
         afd, FD_SETSIZE);
      close_socket(afd);
      return 0;
   }
#endif
#endif

#ifdef FEATURE_EXTERNAL_FILTERS
   mark_socket_for_close_on_execute(afd);
#endif

   set_no_delay_flag(afd);

   csp->cfd = afd;
#ifdef HAVE_RFC2553
   csp->ip_addr_str = malloc_or_die(NI_MAXHOST);
   retval = getnameinfo((struct sockaddr *) &client, c_length,
         csp->ip_addr_str, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
   if (!csp->ip_addr_str || retval)
   {
      log_error(LOG_LEVEL_ERROR, "Can not save csp->ip_addr_str: %s",
         (csp->ip_addr_str) ? gai_strerror(retval) : "Insufficient memory");
      freez(csp->ip_addr_str);
   }
#undef client
#else
   csp->ip_addr_str  = strdup(inet_ntoa(client.sin_addr));
   csp->ip_addr_long = ntohl(client.sin_addr.s_addr);
#endif /* def HAVE_RFC2553 */

   /*
    * Save the name and port of the accepting socket for later lookup.
    *
    * The string needs space for strlen(...) + 7 characters:
    * strlen(haddr[i]) + 1 (':') + 5 (port digits) + 1 ('\0')
    */
   host_addr = (csp->config->haddr[i] != NULL) ? csp->config->haddr[i] : "";
   listen_addr_size = strlen(host_addr) + 7;
   csp->listen_addr_str = malloc_or_die(listen_addr_size);
   retval = snprintf(csp->listen_addr_str, listen_addr_size,
      "%s:%d", host_addr, csp->config->hport[i]);
   if ((-1 == retval) || listen_addr_size <= retval)
   {
      log_error(LOG_LEVEL_ERROR,
         "Server name (%s) and port number (%d) ASCII decimal representation "
         "don't fit into %lu bytes",
         host_addr, csp->config->hport[i], listen_addr_size);
      freez(csp->ip_addr_str);
      freez(csp->listen_addr_str);
      close_socket(csp->cfd);
      return 0;
   }

   return 1;

}


/*********************************************************************
 *
 * Function    :  resolve_hostname_to_ip
 *
 * Description :  Resolve a hostname to an internet tcp/ip address.
 *                NULL or an empty string resolve to INADDR_ANY.
 *
 * Parameters  :
 *          1  :  host = hostname to resolve
 *
 * Returns     :  INADDR_NONE => failure, INADDR_ANY or tcp/ip address if successful.
 *
 *********************************************************************/
unsigned long resolve_hostname_to_ip(const char *host)
{
   struct sockaddr_in inaddr;
   struct hostent *hostp;
#if defined(HAVE_GETHOSTBYNAME_R_6_ARGS) || defined(HAVE_GETHOSTBYNAME_R_5_ARGS) || defined(HAVE_GETHOSTBYNAME_R_3_ARGS)
   struct hostent result;
#if defined(HAVE_GETHOSTBYNAME_R_6_ARGS) || defined(HAVE_GETHOSTBYNAME_R_5_ARGS)
   char hbuf[HOSTENT_BUFFER_SIZE];
   int thd_err;
#else /* defined(HAVE_GETHOSTBYNAME_R_3_ARGS) */
   struct hostent_data hdata;
#endif /* def HAVE_GETHOSTBYNAME_R_(6|5)_ARGS */
#endif /* def HAVE_GETHOSTBYNAME_R_(6|5|3)_ARGS */

   if ((host == NULL) || (*host == '\0'))
   {
      return(INADDR_ANY);
   }

   memset((char *) &inaddr, 0, sizeof inaddr);

   if ((inaddr.sin_addr.s_addr = inet_addr(host)) == -1)
   {
      unsigned int dns_retries = 0;
#if defined(HAVE_GETHOSTBYNAME_R_6_ARGS)
      while (gethostbyname_r(host, &result, hbuf,
                HOSTENT_BUFFER_SIZE, &hostp, &thd_err)
             && (thd_err == TRY_AGAIN) && (dns_retries++ < MAX_DNS_RETRIES))
      {
         log_error(LOG_LEVEL_ERROR,
            "Timeout #%u while trying to resolve %s. Trying again.",
            dns_retries, host);
      }
#elif defined(HAVE_GETHOSTBYNAME_R_5_ARGS)
      while (NULL == (hostp = gethostbyname_r(host, &result,
                                 hbuf, HOSTENT_BUFFER_SIZE, &thd_err))
             && (thd_err == TRY_AGAIN) && (dns_retries++ < MAX_DNS_RETRIES))
      {
         log_error(LOG_LEVEL_ERROR,
            "Timeout #%u while trying to resolve %s. Trying again.",
            dns_retries, host);
      }
#elif defined(HAVE_GETHOSTBYNAME_R_3_ARGS)
      /*
       * XXX: Doesn't retry in case of soft errors.
       * Does this gethostbyname_r version set h_errno?
       */
      if (0 == gethostbyname_r(host, &result, &hdata))
      {
         hostp = &result;
      }
      else
      {
         hostp = NULL;
      }
#elif defined(MUTEX_LOCKS_AVAILABLE)
      privoxy_mutex_lock(&resolver_mutex);
      while (NULL == (hostp = gethostbyname(host))
             && (h_errno == TRY_AGAIN) && (dns_retries++ < MAX_DNS_RETRIES))
      {
         log_error(LOG_LEVEL_ERROR,
            "Timeout #%u while trying to resolve %s. Trying again.",
            dns_retries, host);
      }
      privoxy_mutex_unlock(&resolver_mutex);
#else
      while (NULL == (hostp = gethostbyname(host))
             && (h_errno == TRY_AGAIN) && (dns_retries++ < MAX_DNS_RETRIES))
      {
         log_error(LOG_LEVEL_ERROR,
            "Timeout #%u while trying to resolve %s. Trying again.",
            dns_retries, host);
      }
#endif /* def HAVE_GETHOSTBYNAME_R_(6|5|3)_ARGS */
      /*
       * On Mac OSX, if a domain exists but doesn't have a type A
       * record associated with it, the h_addr member of the struct
       * hostent returned by gethostbyname is NULL, even if h_length
       * is 4. Therefore the second test below.
       */
      if (hostp == NULL || hostp->h_addr == NULL)
      {
         errno = EINVAL;
         log_error(LOG_LEVEL_ERROR, "could not resolve hostname %s", host);
         return(INADDR_NONE);
      }
      if (hostp->h_addrtype != AF_INET)
      {
#ifdef _WIN32
         errno = WSAEPROTOTYPE;
#else
         errno = EPROTOTYPE;
#endif
         log_error(LOG_LEVEL_ERROR, "hostname %s resolves to unknown address type.", host);
         return(INADDR_NONE);
      }
      memcpy((char *)&inaddr.sin_addr, (char *)hostp->h_addr, sizeof(inaddr.sin_addr));
   }
   return(inaddr.sin_addr.s_addr);

}


/*********************************************************************
 *
 * Function    :  socket_is_still_alive
 *
 * Description :  Figures out whether or not a socket is still alive.
 *
 * Parameters  :
 *          1  :  sfd = The socket to check.
 *
 * Returns     :  TRUE for yes, otherwise FALSE.
 *
 *********************************************************************/
int socket_is_still_alive(jb_socket sfd)
{
   char buf[10];
   int no_data_waiting;
#ifdef HAVE_POLL
   int poll_result;
   struct pollfd poll_fd[1];

   memset(poll_fd, 0, sizeof(poll_fd));
   poll_fd[0].fd = sfd;
   poll_fd[0].events = POLLIN;

   poll_result = poll(poll_fd, 1, 0);

   if (-1 == poll_result)
   {
      log_error(LOG_LEVEL_CONNECT, "Polling socket %d failed.", sfd);
      return FALSE;
   }
   no_data_waiting = !(poll_fd[0].revents & POLLIN);
#else
   fd_set readable_fds;
   struct timeval timeout;
   int ret;

   memset(&timeout, '\0', sizeof(timeout));
   FD_ZERO(&readable_fds);
   FD_SET(sfd, &readable_fds);

   ret = select((int)sfd+1, &readable_fds, NULL, NULL, &timeout);
   if (ret < 0)
   {
      log_error(LOG_LEVEL_CONNECT, "select() on socket %d failed: %E", sfd);
      return FALSE;
   }
   no_data_waiting = !FD_ISSET(sfd, &readable_fds);
#endif /* def HAVE_POLL */

   return (no_data_waiting || (1 == recv(sfd, buf, 1, MSG_PEEK)));
}


#ifdef FEATURE_EXTERNAL_FILTERS
/*********************************************************************
 *
 * Function    :  mark_socket_for_close_on_execute
 *
 * Description :  Marks a socket for close on execute.
 *
 *                Used so that external filters have no direct
 *                access to sockets they shouldn't care about.
 *
 *                Not implemented for all platforms.
 *
 * Parameters  :
 *          1  :  fd = The socket to mark
 *
 * Returns     :  void.
 *
 *********************************************************************/
void mark_socket_for_close_on_execute(jb_socket fd)
{
#ifdef FEATURE_PTHREAD
   int ret;

   ret = fcntl(fd, F_SETFD, FD_CLOEXEC);

   if (ret == -1)
   {
      log_error(LOG_LEVEL_ERROR,
         "fcntl(%d, F_SETFD, FD_CLOEXEC) failed", fd);
   }
#else
#warning "Sockets will be visible to external filters"
#endif
}
#endif /* def FEATURE_EXTERNAL_FILTERS */

/*
  Local Variables:
  tab-width: 3
  end:
*/
