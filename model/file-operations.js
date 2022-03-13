/**
 * Generally this module can be used to move files from one place to another using promises by pify
 *
 */

const fs = require('fs');
const pify = require('pify');

async function moveFile(oldPath, newPath) {
  await pify(fs.rename)(oldPath, newPath);
}

async function createFolder(folderPath, folderName) {
  if (!fs.existsSync(folderPath + folderName)) {
    await pify(fs.mkdirSync)(folderPath + folderName, { recursive: true });
  }
}

async function listFiles(folderPath) {
  return (await pify(fs.readdir)(folderPath)) || [];
}

module.exports.moveFile = moveFile;
module.exports.createFolder = createFolder;
module.exports.listFiles = listFiles;
