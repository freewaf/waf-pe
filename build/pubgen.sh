
DESFILENAME=./modules/$2/$2_public.h
SRCFILENAME=./modules/$2/$2_public.h.in

echo "Construct $2 module public debug MACRO header file"

rm -rf  $DESFILENAME

cat - $SRCFILENAME <<EOF > $DESFILENAME
EOF

sed -i "/endif/i\\$(echo $1)" $DESFILENAME
