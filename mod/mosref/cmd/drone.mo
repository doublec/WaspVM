 mf� �
	    
	    
	    
	    
	     	 
	 
           ����
	  
	  � �   � �   � �
	  � �   � �
	  � �   � �
	  � �  � �
	  � �
	  � � � �� ��g�m
	    
	  � � � �
	  � � � � � �	 ����
	    ��
	  � � � �	 � � � � � � � �
  ����
	   ! 
	 " 
	 # ��    $ ��
	 % � �� �
 
	 &  ' 
	 ( � � � � � �	 
	 ) � �  � �
	 * � �  + � � 
	 , � � � �   ,����

	  � �  � �
	 - � � � �
	 . � � � �
	 / � � � �
	 &  0 
	 " � �   1 
	 2  3��� ��� � �� � 4��� �  5�<��
	 6 � �  
	 &  7 ��  8 
	 9 
	 : � �     $ ��H
	 ; ��  �� �� �� �� �L�M <�o��
	 6 � �  
	 &  = ��  > 
	 9 
	 : � �     $ ��~
	 ? �� 
	 @ ��  ��� �� ���
� � ��
	 9 � �  � �
	 &  A ��  B 
	 C � �   $ 
	 D �� � 
	 E �� 
	 F 	 G 	 H � �   , I� � 
	 V 
	 Q 	 W � �   ;�f��
	 X � �  ��  � �
	 9 � � � �
	 # � � � �
	 Y � �
	 Z � �  � �
	 P 
	 Q � � � �  � � 
	 L � � � �
	 P  U � � 
	 [ � � �%
	 \ 
	 9 � �   R �\
	 @ � � � �
	 9 � � � �
	 # � � � �
	 ] � � � � � �� ��[
	 Q � � 
	 ^ � �  
	 _ � �  �[�\
	 `  a  b � �  
	 c 
	 d  ;  �z
	 d  ; �{	 e  ;
	 V 
	 Q 	 f � �   ;����
	  � �  � �
	 M � � � � � �
	 Q 
	 S � �  
	 g � �  
	 h � �   
	 c 
	 d  ;  ��
	 d  ; ��	 e  ; i� �
	 V 
	 Q 	 W �   �!��

	 X � �  �� � �
	 9 � � � �
	 # � � � �
	 P � � � � 
	 L � � � �
	 P  U � � 
	 k � � �� ��
	 `  a  l � �  
	 c 
	 d    �5
	 d   �6	 e  
	 V 
	 Q 	 f �   �M��
	 j � �  
	 c 
	 d    �a
	 d   �b	 e   module mosref/cmd/drone import mosref/shell mosref/node mosref/listener bind-mosref-cmd drone drone <file> <id> <platform> string-append 9Creates a new drone executable for the specified platform 5 and places it at file, then spawns a listener on the : current node.  When the drone connects to the listener, a 5 the drone will be bound to the specified identifier. 	cmd-drone req-path mosref-shell-console  for drone executable req-term  drone identifier  drone platform mosref-shell-node make-private-key 	node-addr send-err 1 node address unknown, use set addr to assign one 	node-port node-make-sin 
anon-fn-41 Could not compile drone. make-drone-exe 
anon-fn-44 Could not write file  format cadr . put-node-file 	send-line Drone executable created. make-drone-node find-public-key set-node-prop! platform spawn-drone-listener node-id drone-node-sin drone-node-ecdh Listening for drone on  ... spawn 
anon-fn-47 attempt-affiliation 
anon-fn-51 	traceback ERROR: Listener for  failed,  car 
error-info node-sin-listen 
anon-fn-56 ERROR: Affilation of  	 failed,  console-affiliation cdr Drone   affiliated from address  format-ipv4 set-node-online! set-node-bridge! spawn-endpoint console-endpoint console-broken �� �
	    
	   J 	 K� � 
	 L � �
	 M � �� �
	 N � �  � �
	 O � � � � 
	 P 
	 Q  R 
	 S � �  
	 T � �   
	 P  U  mosref/patch *drone-bridge* wait mosref-sin-listen make-reserved-lane patch2 send list connect 	peer-addr lane-tag close make-multimethod <drone-node> spawn-node-program 
make-queue drone-node-bridge pair? eq? find-reserved-lane 	lane-xmit 	lane-recv error mosref ,Bogus message while waiting for session lane 	function? 
get-global refuse-method <console-node> input output #� � 
	    
	 P 
	 j 
	 L    make-mosref-sin string? =Bogus message while waiting for service identification number