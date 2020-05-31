lim=10^100; x2=0;  x3=0;  k2=1;  k23=1;
while(k2<lim,k23=k2;while(k23<lim,if(isprime(k23+1),print(k23+1));k23*=3;);k2*=2;);
quit
