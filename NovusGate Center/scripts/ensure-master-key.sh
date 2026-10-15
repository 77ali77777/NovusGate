
if [ -f "@@ENV_FILE@@" ] && ! grep -q "^MASTER_KEY=." "@@ENV_FILE@@"; then
  sed -i '/^MASTER_KEY=$/d' "@@ENV_FILE@@"
  echo "MASTER_KEY=@@MASTER_KEY_GEN@@" >> "@@ENV_FILE@@"
fi
