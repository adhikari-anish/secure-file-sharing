const FileSharing = artifacts.require("FileSharing");

module.exports = function(deployer) {
  deployer.deploy(FileSharing);
};
