export PATH:=.env/bin:$(PATH)

run: .env
	python inventory.py > output.html
	@echo "Now bring up output.html in a browser"

install: .env

.env:
	python3 -m venv .env
	curl https://raw.githubusercontent.com/pypa/pip/master/contrib/get-pip.py | python
	pip install -r requirements.txt
