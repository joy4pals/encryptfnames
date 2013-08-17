echo "This script will now mount wrapfs ONLY and not ext3"
echo "This assumes wrapfs in already insmoded"

LOWER_MNTPT=/n/scratch
UPPER_MNTPT=/tmp
mount -t wrapfs -o debug=32,mmap $LOWER_MNTPT $UPPER_MNTPT

echo "file systems mounted successfully.."
