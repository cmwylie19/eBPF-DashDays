.PHONY: rebuild

refetch:
	@git fetch
	@git rebase origin/case case
	@git pull origin case 
