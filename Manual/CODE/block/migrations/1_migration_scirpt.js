const exo = artifacts.require('SmartContract')
module.exports = (deployer)=>{
    deployer.deploy(exo)
}