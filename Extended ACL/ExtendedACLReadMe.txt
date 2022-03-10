##
Pranav Mahindru 
B00823022

ACL CHECKING

--> I am checking ACL number should be in between 100 to 199 in the first line of ACL
--> first line ACL number should be equal to the last line ACL number 
--> IPS in the ACL whether it is source or destination should be valid otherwise it will show you error
--> MASK in the ACL whether it is source or destination should be valid otherwise it will show you error

I am checking Protocol id with Port numbers 

example I am Only taking 3 main protocols 
TCP --> 20, 21, 20-21, 22, 23, 25, 80 if it is not matched then it will give you error
UDP --> 53, 69, 161 if it is not matched then it will give you error 
IP --> all are port can go permit or deny as per the statement wants

I am not checking for the ICMP and IGMP and also i am not taking then as an input

In the user ip text file 

IN-Valid IPS
(NOT saving Source IP, Destination IP, port Number) in the ArrayList 

Valid IPS 
(saving Source IP, Destination IP, port Number) in the ArrayList