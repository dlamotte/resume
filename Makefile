help:
	@echo 'usage: make [target]'
	@echo ''
	@echo '    help        this help document'
	@echo '    serve       start development server'
	@echo ''

serve:
	browser-sync start --server --files "css/*.css"

.PHONY: help serve
