.PHONY: rebuild

refetch:
	@git fetch
	@git rebase origin/case case
	@git pull origin case 
	
repush:
	@git add .
	@git commit -s -am 'update'
	@git push origin case
