  �� � 
	    
	    
	      
	   	  
       �i��
	  � �   � �
	  � �  � �
	  � �  � �  �E� � 
	  ��  �� � �
	  � � �N�h �Z��
�� 
	  � �  �h
	  � �  � � 
� �   module mosref/cmd/on import mosref/shell bind-mosref-cmd on on <node-id> [<command>] string-append ;Instructs the console to perform subsequent commands on the ? specified node.  If an optional command is included, only that ? command will be performed on that node before returning to the  current node. cmd-on req-node   mosref-shell-node set-mosref-shell-node! revert-node 	tc-empty? revert-node-before-err re-error do-mosref-cmd