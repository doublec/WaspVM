; Copyright (C) 2006, Ephemeral Security, LLC
; Modifications (C) 2013, Chris Double <chris.double@double.co.nz>
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

(module "mosref/scanner")
(import "lib/with-io")
(import "lib/catch")
(import "mosref/format")
;(import "mosref/model")

(define (resolve-host-spec host-spec)
  (cond ((list? host-spec)
         (map (function (resolve-host item)
                 (if (string? item) (resolve-ipv4 item) item))
              host-spec))

        ((string? host-spec)
         (resolve-ipv4 host-spec))

        (else host-spec)))

(define (single-iter x)
  (define k #f)
  (lambda ()
    (when k (error 'done))
    (set! k #t)
    x))

(define (gen-scan-port port-spec)
  (if (list? port-spec)
    (integer-range (car port-spec) (+ (cadr port-spec) 1))
    (single-iter port-spec)))

(define (gen-scan-ports port-specs)
  (apply join-iters (map gen-scan-port port-specs)))

(define (gen-scan-addr addr-spec)
  (if (list? addr-spec)
    (integer-range (car addr-spec) (+ (cadr addr-spec) 1))
    (single-iter addr-spec)))

(define (gen-scan-addrs addr-specs)
  (apply join-iters (map gen-scan-addr addr-specs)))

;; Consumes a list of host specs, a list of port specs, and generates
;; combinations of hosts and ports to scan.

(define (gen-scan-tasks scan-hosts scan-ports)
  (define scan-addrs (map resolve-host-spec scan-hosts))

  (define port-iter (gen-scan-ports scan-ports))
  (define port #f)

  (define addr-iter #f)

  (define (next-port) 
    (set! port (port-iter))
    (set! addr-iter (gen-scan-addrs scan-addrs)))

  (next-port)

  (define (next-task)
    (guard (lambda (err)
             (unless (eq? (error-key err) 'done)
               (re-error err))
             (next-port)
             (next-task))
      (list (addr-iter) port))))

(define-macro (repeat count . body)
  `(let ((%ctr ,count))
     (until (<= %ctr 0)
       (set! %ctr (- %ctr 1))
       ,@body)))

(define (scan-port host port lapse yield)
  ;(define f-host (format-ipv4 host))
  ;(print (string-append "Scanning " f-host ":" (format port) "...\n"))
  (define conn (guard (lambda (e)  ;(print "Connection error while scanning: ")
                                   ;(print f-host)
                                   ;(print ":")
                                   ;(print (format port))
                                   ;(print " -- \n")
                                   ;(traceback e) 
                        #f) 
                 (tcp-connect host port)))
  (unless conn (return))
;  (define t (timeout lapse (output conn)))
;  (define evt (wait conn))

  ;(send 'close conn)
  ;(close-stream conn)

;  (when (eq? evt 'timeout) 
    ;TODO: Report a lapse.  If a host gives both a lapse and reset, we're probably
    ;      scanning too hard.
    ;(print (string-append "... Timeout " f-host ":" (format port) ".\n"))
;    (send 'close conn)
;    (close-stream conn)
;    (return))

  ;(wait conn) ; Discharging the timeout..
 ; (cancel-timeout t)

;  (when (eq? evt 'close)
;    ;TODO: Report a reset.
;    (return))

  (send 'close conn)
;  (close-stream conn)

;  (when (eq? evt 'connect)
;    (print (string-append "... Connect " f-host ":" (format port) ".\n"))
    (send (list 'connect host port) yield)
    (return)

 
;  (print (string-append "... Failure " f-host ":" (format port) " -- "
;                        (format evt) "\n"))
  )

; Waits a random amount of time.
(define (random-delay min-delay max-delay)
  (define c (make-queue))
  (timeout (random-integer min-delay max-delay) c)
  (wait c))
  
; Given a list of hosts, a list of ports, a number of worker threads to spawn
; and a timeout in milliseconds to wait for any given connection attempt -- 
; spawns the required threads and yields a channel that will report each
; successful connection, and, when all possible combinations have been tried,
; a done.

(define (spawn-scanners hosts ports conns lapse)
;  (print "SCAN: ")
;  (print " hosts: ")
;  (print (format hosts))
;  (print " ports: ")
;  (print (format ports))
;  (print " conns: ")
;  (print (format conns))
;  (print " lapse: ")
;  (print (format lapse))
;  (print "\n")
  (define results (make-queue))
  (define next-task (gen-scan-tasks hosts ports)) 
  (define done-sent #f)

  (define (terminate)
    (set! conns (- conns 1))
    (when (= conns 0)
      (send 'done results)
      (set! terminate (lambda () (halt))))
    (halt))

  (repeat conns
    (spawn (function (scanner-process)
              (random-delay 100 500)
              (forever
                (define evt (guard (lambda (err)
                                     (unless (eq? (error-key err) 'done)
                                       (re-error err))
                                     (terminate))
                              (next-task)))
                
                (cond ((pair? evt)
                       (scan-port (car evt) (cadr evt) lapse results))

                      ((eq? evt 'done)
                       (return))

                      ((eq? evt 'signal-done) 
                       (send 'done results)
                       (return)))))))
  results)

(export spawn-scanners)

