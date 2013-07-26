#!   /bin/bash 
TF=/tmp/$$ 
flag=0
sed   -e   's/:/   /g '   -e   's/"/   /g '   $1   >   $TF 
for   line   in   `cat   $TF` 
do 
        for   fn   in   $line 
        do 
                if   [   `echo   $fn   |   grep   'MODSEC_VERSION_BUILD'`   ];then
			flag=1
		else 
			if  [   $flag -eq 1 ];then
			NEW=$fn
			NEW=` (expr $( expr $NEW + 1 ) % 1000)`
			sed  "/MODSEC_VERSION_BUILD/{ s/$fn/$NEW/; }" $1 > $TF
			mv $TF $1
			rm -f $TF 
			exit
			fi	
		fi
	done
done

rm -f $TF
		
 
                        
