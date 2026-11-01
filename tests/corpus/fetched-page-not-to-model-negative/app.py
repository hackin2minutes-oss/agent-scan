import requests
def save(url):
    page = requests.get(url).text
    open('out.txt', 'w').write(page)
