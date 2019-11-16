



xss = [
  ''' <hr> ''',
  ''' <script>alert(1);</script> ''',
  ''' "'><iframe> ''',


]


sqli = [
  ''' ' or 1='1 ''',
  ''' " or 1="1 ''',
  
]