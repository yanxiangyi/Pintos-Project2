make
pintos -v -k -T 60 --bochs  --filesys-size=2 -p tests/userprog/args-multiple -a args-multiple -- -q  -f run 'args-multiple some arguments for you!'


