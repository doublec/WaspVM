; Copyright (C) 2006, Ephemeral Security, LLC
; Modifications (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
; 
; This library is free software; you can redistribute it and/or modify it 
; under the terms of the GNU Lesser General Public License, version 2.1
; as published by the Free Software Foundation.
; 
; This library is distributed in the hope that it will be useful, but WITHOUT 
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
; FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License 
; for more details.
; 
; You should have received a copy of the GNU Lesser General Public License 
; along with this library; if not, write to the Free Software Foundation, 
; Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

; field 1: socks version number, 1 byte, must be 0x04 for this version
; field 2: command code, 1 byte:-
;   0x01 = establish a tcp/ip stream connection
;   0x02 = establish a udp datagram port binding
; field 3: network byte order port number, 2 bytes
; field 4: network byte order ip address, 4 bytes
; field 5: the user id string, variable length, terminated with a null (0x00)
; field 6: dns address string if first three bytes of field 3 are null, 
;          terminated with a null (0x00).

(module "lib/socks-server.ms")
(import "lib/patch")
(import "lib/tcp-server")
(import "lib/trace")

(define (read-to-zero! str what)
  (define res (make-string (string-length str)))
  (until (empty-string? str)
    (define ch (string-read-byte! str))
    (if (= ch 0) (return res)
                 (string-append! res ch)))
  (error 'socks (string-append what " incomplete") res))

(define (parse-socks4-request str)
  (define ver (string-read-byte! str))
  (unless (= ver 4) (error 'socks "expected socks version 4" ver))
  
  (define cmd (string-read-byte! str))
  (define proto (case cmd 
                  ((1) 'tcp)
                  ((2) 'udp)
                  (else (error 'socks "unrecognized socks command" cmd))))
  
  (define portno (string-read-word! str))
  (define addr (string-read-quad! str))

  (define auth (read-to-zero! str "user authentication"))

  (when (= 0 (& addr $FFFFFF00))
    (set! addr (read-to-zero! str "address")))

  (list auth proto addr portno))

; field 1: null byte
; field 2: status, 1 byte:-
;   0x5a = request granted, 
;   0x5b = request rejected or failed,
;   0x5c = request failed because client is not running identd (or not 
;          reachable from the server)
;   0x5d = request failed because client's identd could not confirm the user 
;          id string in the request
; field 3: network byte order port number, 2 bytes
; field 4: network byte order ip address, 4 bytes

(define (format-socks4-response granted portno addr)
  (define str (make-string))
  (string-append-word! str (if granted $5A $5B)) 
  (string-append-word! str portno)
  (string-append-quad! str (if (string? addr) 0 addr))
  str)

(export format-socks4-response parse-socks4-request)

(define (spawn-socks4-proxy portno auth-fn conn-fn)
  (define (socks4-proxy-session)
    (define e #f)
    (define (next what)
      (set! e (wait 10000))
      (if (eq? e 'timeout)
        (error 'socks (string-append "timeout while waiting for " what))
        e))

    (define f #f)
    (define addr #f)
    (define portno #f)
    
    (guard (lambda (err)
             (send (format-socks4-response #f 0 0))
             (send 'close)
             (unless (eq? (error-key err) 'socks)
               (re-error err))
             (halt))

      (unless (string? (next "socks request"))
        (error 'socks "expected request" e))

      (define r (parse-socks4-request e))

      (unless (eq? 'tcp (cadr r))
        (error 'socks "only tcp requests can be proxied"))

      (unless (auth-fn (car r))
        (error 'socks "authentication failed"))

      (set! r (cdr (cdr r)))
      (set! addr (car r))
      (set! portno (cadr r))

      (when (string? addr)
        (guard (lambda (x)
                 (error 'socks (string-append "cannot resolve address " addr)))
          (set! addr (resolve-ipv4 addr))))

      (set! f (conn-fn addr portno)))

    (send (format-socks4-response #t addr portno))
    (define c-xmit (output))
    (define c-recv (input))

    (define f-xmit #f)
    (define f-recv #f)

    (cond ((pair? f) (set! f-xmit (car f))
                     (set! f-recv (cadr f)))
          ((connection? f) (set! f-xmit (output f))
                           (set! f-recv (input f)))
          ((eq? f #f) (send 'close c-xmit)
                      (return)))
    (patch (input) f)
    (patch f (output)))

  (spawn-tcp-server portno socks4-proxy-session))

(export spawn-socks4-proxy)
