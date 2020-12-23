nsupdate - Dynamic DNS update utility

build:
======
~~~~
$ rebar3 escriptize
~~~~

run:
====
~~~~
$ ./nsupdate -k my.zone.example.key
>> server 203.0.113.42
>> zone my.zone.example.
>> local 198.51.100.27 8851
>> update add newhost.my.zone.example 3600 A 192.0.2.110
>> send
~~~~

notes:
====

- `prereq` is not implemented
- `show` is not implemented
- `send` will execute the query and terminate the program
- update will always be sent over TCP