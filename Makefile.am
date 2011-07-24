SUBDIRS = src test

# Avoid: .svn - svn directories
#        *~  - emacs backups
#        .#* - merge originals
#
# *~ and .#* only occur when a whole directory without it's own Makefile.am
# is distributed (such as src/os-*).
dist-hook:
	find $(distdir) \( -name .svn -type d \) -o -name "*~" -o -name ".#*" -exec rm {} \;
