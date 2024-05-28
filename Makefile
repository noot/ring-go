.SILENT:

#####################
###    General    ###
#####################

.PHONY: help
.DEFAULT_GOAL := help
help:  ## Prints all the targets in all the Makefiles
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: list
list:  ## List all make targets
	@${MAKE} -pRrn : -f $(MAKEFILE_LIST) 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | sort

#####################
####   Testing   ####
#####################

.PHONY: test_all
test_all:  ## runs the test suite
	go test -v -p 1 ./... -mod=readonly -race

##########################
####   Benchmarking   ####
##########################

.PHONY: benchmark_all
benchmark_all:  ## runs the benchmark suite
	go test -bench=. -benchmem -cpuprofile=cpu.prof -memprofile=mem.prof

###########################
###   Release Helpers   ###
###########################

# List tags: git tag
# Delete tag locally: git tag -d v1.2.3
# Delete tag remotely: git push --delete origin v1.2.3

.PHONY: tag_bug_fix
tag_bug_fix: ## Tag a new bug fix release (e.g., v1.0.1 -> v1.0.2)
	@$(eval LATEST_TAG=$(shell git tag --sort=-v:refname | head -n 1))
	@$(eval NEW_TAG=$(shell echo $(LATEST_TAG) | awk -F. -v OFS=. '{ $$NF = sprintf("%d", $$NF + 1); print }'))
	@git tag $(NEW_TAG)
	@echo "New bug fix version tagged: $(NEW_TAG)"
	@echo "Run the following commands to push the new tag:"
	@echo "  git push origin $(NEW_TAG)"
	@echo "And draft a new release at https://github.com/pokt-network/smt/releases/new"


.PHONY: tag_minor_release
tag_minor_release: ## Tag a new minor release (e.g. v1.0.0 -> v1.1.0)
	@$(eval LATEST_TAG=$(shell git tag --sort=-v:refname | head -n 1))
	@$(eval NEW_TAG=$(shell echo $(LATEST_TAG) | awk -F. '{$$2 += 1; $$3 = 0; print $$1 "." $$2 "." $$3}'))
	@git tag $(NEW_TAG)
	@echo "New minor release version tagged: $(NEW_TAG)"
	@echo "Run the following commands to push the new tag:"
	@echo "  git push origin $(NEW_TAG)"
	@echo "And draft a new release at https://github.com/pokt-network/smt/releases/new"