
docs/index.html: .jsdoc.json src/*.js
	npx jsdoc src/*.js --configure .jsdoc.json --destination docs --verbose

package-lock.json: package.json 
	npm install
	touch $@
node_modules: package-lock.json


docs: docs/index.html


.PHONY: preview-package publish-docs publish-package test

preview-package: test
	npm pack --dry-run .

publish-package: test
	npm publish --access public .


CURRENT_BRANCH = $(shell git branch | grep \* | cut -d ' ' -f2)
publish-docs:
	git branch -D gh-pages || true
	git checkout -b gh-pages
	echo "\nBuilding docs"
	make docs
	ln -s docs v$$( cat package.json | jq -r .version )
	@echo "\nAdding docs..."
	git add -f docs
	git add v$$( cat package.json | jq -r .version )
	@echo "\nCreating commit..."
	git commit -m "JSdocs v$$( cat package.json | jq -r .version )"
	@echo "\nForce push to gh-pages"
	git push -f origin gh-pages
	git checkout $(CURRENT_BRANCH)


test: node_modules
	npm run test
