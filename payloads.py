#!/usr/bin/env python
# -*- coding: utf-8 -*-



xss = [
  ''' <hr> ''',
  ''' <script>alert(1);</script> ''',
  ''' "'><iframe> ''',
  ''' "'><IMG SRC=jAVasCrIPt:alert(‘XSS’)> ''',

]


sqli = [
  ''' ' or 1='1 ''',
  ''' " or 1="1 ''',
  
]


utf8s = [
  '🦄','D̡̢̧̨̡̢̧̨̡̢̧̨̰̰̱̲̳̠̣̤̥̦̪̰̰̱̲̳̠̣̤̥̦̪̰̰̱̲̳̠̣̤̥̦̪̿̿̿̿̿̿̿̿̿̿̿̾̿̾̿̾'
]