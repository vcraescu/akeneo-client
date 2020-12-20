generate:
	swagger generate client -f https://raw.githubusercontent.com/akeneo/pim-api-docs/master/content/swagger/akeneo-web-api.json \
		--skip-validation --name=akeneo