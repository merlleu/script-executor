echo "Hello World"


echo "Environment Variables"
echo "---------------------"
for var in $(env | cut -d= -f1)
do
  echo "$var = ${!var}"
done
echo "---------------------"


# sleep 1s and count to 10
for i in {1..10}
do
  echo $i
  sleep 1s
done
echo "Done"