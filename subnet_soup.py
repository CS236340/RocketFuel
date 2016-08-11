from bs4 import BeautifulSoup
import os
import re

def getprefixes(html_file_adress):
    dir = os.path.dirname(__file__)
    filename = os.path.join(dir, html_file_adress)
    page = open(filename,'r')
    soup = BeautifulSoup(page, 'html.parser')
    soup = soup.find(id='prefixes')
    code = soup.get_text()
    prefix = re.findall('\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}', code)
    len = re.findall('/\d{1,2}', code)
    len = [int(re.sub('/', '', i)) for i in len]
    result = list(zip(prefix,len))
    return result
