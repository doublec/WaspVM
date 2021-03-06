(import "lib/waspc")
(import "lib/build")

(define (main . args)
  (define base-dir #f)
  (define mod-dir #f)
  (define inc-dir #f)
  (define lib-dir #f)
  (define stub-dir #f)
  (define bin-dir #f)
  (define good #f)

  (define (do-config-prompt title current guess-fn description)
    (define val (or current (guess-fn)))
    (send (string-append "-- " 
                         title (if val (string-append ": " (format val)) "")
                         " --" *line-sep*))
    (send (string-append description *line-sep* ">> "))
    (define ans (strip (wait)))
    (if (empty-string? ans) val ans))
  
  (define-macro (config var title guess . descr-lines)
    `(set! ,var 
       (do-config-prompt ,title ,var (lambda () ,guess)
                         ,(apply string-join *line-sep* descr-lines))))
  
  (define (do-confirm lead . items)
    (send (apply string-append 
                 lead *line-sep*
                 (map (lambda (item) 
                        (string-append "    " (car item) ": " (cadr item) 
                                       *line-sep*))
                      items)))
  
    (send "Yes / No? >> ")
  
    (define ans (strip (wait)))
    (send "\n")
    (or (string-begins-with? ans "y")
        (string-begins-with? ans "Y")))
  
  (define-macro (confirm lead . rest)
      `(if (do-confirm ,lead 
                       ,@(map (lambda (item) (cons 'list item))
                              rest))
         (return)))
  
  (define (mkdir . items)
    (run-command (string-append "mkdir -pm 0755 " 
                                (apply string-join " " items))))
  
  (define (copy . items)
    (run-command (string-append "cp -rp " (apply string-join " " items))))
  
  (define (chmod mask . paths)
    (run-command (string-append "chmod " mask " " (apply string-join " " 
                                                         paths))))
  
  (define (configure)
    (forever
      (config base-dir "Base Directory" "/usr/local"
        "Most UNIX users place applications that are not managed by their"
        "environment's package manager in subdirectories of /usr/local.  WaspVM"
        "will use this preference to guess sane defaults for the rest of the"
        "install process.")
 
      (config mod-dir "Module Directory" (string-append base-dir 
                                                        "/lib/waspvm")
        "WaspVM includes a considerable number of add on modules, and must be" 
        "able to find them to compile applications.  The default location is"
        "derived from your Base Directory, and is fairly standard for"
        "development environments.")
 
      (config lib-dir "Library Directory" (string-append base-dir "/lib")
        "Shared libraries make it possible for a single installation of Wasp to"
        "be shared between several programs.  This directory must be registered"
        "with the host environments.  The default complies with ancient UNIX"
        "tradition.")
    
      (config inc-dir "Include Directory" (string-append base-dir "/include")
        "Header files are provided for third-party subsystems.  This directory"
        "is usually checked by your computer's C compiler.  If you don't have"
        "a C compiler, or you do not plan on compiling subsystems, the default"
        "is probably safe.")

      (config stub-dir "Stub Directory" (string-append mod-dir "-stubs")
        "WaspVM also includes a number of binary \"stubs\" which contain the"
        "bootstrap program that must begin any compiled WaspVM application."
        "The default location keeps these stubs separate from the module"
        "directory since they are not WaspVM object packages.")
  
      (config bin-dir "Binary Directory" (string-append base-dir "/bin")
        "WaspVM includes several utilities, in addition to the \"waspvm\""
        "interactive environment.  These utilities will, by default, be placed"
        "in the bin subdirectory of the Base Directory.")
  
      (confirm
        "You have selected the following directories for installation:"

        (" Module Directory" mod-dir)
        ("Library Directory" lib-dir)
        ("Include Directory" inc-dir)
        (" Binary Directory" bin-dir)
        ("   Stub Directory" stub-dir))))
  
  (configure)
  
  (write-data-file "site/config.ms"
     (string-append ";;; Generated by bin/install.ms" *line-sep*
                    "(set-site-config! 'stub-path \"" stub-dir "\")" *line-sep*
                    "(set-site-config! 'bin-path \"" bin-dir "\")" *line-sep*
                    "(set-site-config! 'mod-path '(\".\" \"" mod-dir "\"))" 
                    *line-sep*))
  
  (waspc "site/config.ms")
  
  (define mod-sys-dir (string-append mod-dir "/sys"))
  
  (mkdir bin-dir mod-dir mod-sys-dir stub-dir inc-dir)
  
  (copy "../vm/waspvm.h" "../vm/waspvm" inc-dir)
  ;(copy "lib/*" lib-dir) TODO: No shared libraries or static ones, atm.
  ;(copy "../waspvm" bin-dir)
  (copy "bin" mod-dir)
  (copy "core" mod-dir)
  (copy "lib" mod-dir)
  (copy "site" mod-dir)
  (copy "waspdoc" mod-dir)
  ;(copy (string-append "sys/*" *plugin-ext*) mod-sys-dir)
  (copy "../stubs/*" stub-dir)
  
  ; Re-link, so we have the new site config..
  (define wasp-bin (string-append bin-dir "/wasp"))
    
  (write-data-file wasp-bin (build-exe *platform* "bin/wasp")) 
  
  ; Re-link, so we have the new site config..
  (define waspc-bin (string-append bin-dir "/waspc"))
    
  (write-data-file waspc-bin (build-exe *platform* "bin/waspc")) 
  
  ; Re-link, so we have the new site config..
  (define waspdoc-bin (string-append bin-dir "/waspdoc"))
    
  (write-data-file waspdoc-bin (build-exe *platform* "bin/waspdoc")) 

  (chmod "-R 0755" mod-dir) ;stub-dir 
  
  (chmod "0755" bin-dir wasp-bin waspc-bin waspdoc-bin))

