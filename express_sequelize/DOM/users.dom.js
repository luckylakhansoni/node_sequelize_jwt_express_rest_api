const db = require("../models");
const User = db.user;

module.exports.createRecord = async (query)=>{
    try {
        let data = await User.create(query)
        return data
    } catch (error) {
        throw error
    }
}
module.exports.singleRecord = async (query) => {
    try {
        let data = await User.findOne(query)
        return data
    } catch (error) {
        throw error
    }
}

module.exports.updateRecord = async (body, query) => {
    try {
        let data = await User.update(body, query)
        return data
    } catch (error) {
        throw error
    }
}
module.exports.activeUser = async (query) => {
    try {
        let data = await User.count(query)
        return data
    } catch (error) {
        throw error
    }
}

module.exports.findAllUsers = async(query)=> {
    try {
        let data = await User.findAll(query)
        return data
    } catch (error) {
        throw error
    }
}

module.exports.deleteUser = async(query)=> {
    try {
        let data = await User.destroy(query)
        return data
    } catch (error) {
        throw error
    }
}


module.exports.findAllUsers = async(query)=> {
    try {
        let data = await User.findAll(query)
        return data
    } catch (error) {
        throw error
    }
}
module.exports.findAndCount = async(query)=> {
    try {
        let data = await User.findAndCountAll(query)
        return data
    } catch (error) {
        throw error
    }
}

module.exports.recordCount = async(query)=> {
    try {
        let data = await User.count(query)
        return data
    } catch (error) {
        throw error
    }
}

