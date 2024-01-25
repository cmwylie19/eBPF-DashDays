.PHONY: rebuild

rebuild:
	@git fetch
	@git rebase origin/case case
	@git pull origin case 
