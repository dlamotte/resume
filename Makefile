BUCKET ?= dlamotte.io

help:
	@echo 'usage: make [target]'
	@echo ''
	@echo '    deploy      deploy updated resume'
	@echo '    help        this help document'
	@echo '    serve       start development server'
	@echo ''

deploy:
	cd src && find *.html -type f -exec \
		aws s3api put-object --bucket $(BUCKET) --key {} --body {} --content-type text/html \;
	cd src && find *.txt -type f -exec \
		aws s3api put-object --bucket $(BUCKET) --key {} --body {} --content-type text/plain \;
	cd src && find css -type f -exec \
		aws s3api put-object --bucket $(BUCKET) --key {} --body {} --content-type text/css \;

serve:
	browser-sync start --server --files "css/*.css"

.PHONY: help serve
