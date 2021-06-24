const fs = require('fs');
const moment =  require("moment")

const helper = require("../utils/helper");
const Bcrypt = require("bcryptjs");
let db = require("../models/index");
const Op = db.Sequelize.Op;
const sequelize = db.Sequelize
const { USER_TYPE } = require("../utils/constant");
const {
  createRecord,
  singleRecord,
  updateRecord,
  activeUser,    
} = require("../DOM/users.dom");
const { fileUpload, csvUpload, fileUploadPdf } = require('../utils/helper')
exports.register = async (req, res) => {
  try {
    let body = req.body;
    let query = {};
    query.where = {
      email: body.email,
    };
    let emailChecking = await singleRecord(query);
    let emailBranch = await branch.singleRecord(query);
    if (emailChecking || emailBranch) {
      res.status(400).json({message:"Email already register"});
      return;
    }
    body.password = await helper.createPassword(body.password);
    let user = await createRecord(body);
    let jwt = await helper.jwtToken(user.user_id);
    res.setHeader("token", `Bearer ${jwt}`);
    user.jwtToken = jwt;
    if (body.user_type === USER_TYPE.station_emp) {
      let id = await helper.createStationId();
      let bodybject = {
        station_id: `j${id}${user.user_id}`,
      };
      let queryObject = {
        where: { user_id: user.user_id },
      };
      await updateRecord(bodybject, queryObject);
    }
    user = user.toJSON();
    delete user.password;
    res.send(user);
  } catch (error) {
    console.log({ error });
    res.status(500).json("Error: " + error);
  }
};

exports.signin = async (req, res) => {
  try {
    let body = req.body;
    let user;
    // checking email registerd ot not
    let query = {
      where: {},
    };
    query.where.email = body.email
    query.user_type = body.user_type;
    user = await singleRecord(query);
    if (!user) {
      // for branch user 
      let brachObj = await branch.singleRecord({where: {email: body.email}})
      if(!brachObj) {
        res.status(400).json({message: "User not found"});
        return;
      }
      brachObj = JSON.parse(JSON.stringify(brachObj))
      let type = 'branch_user'
      let jwtForBranch = await helper.jwtToken(brachObj.branch_id, type);
      res.setHeader("x-access-token", `Bearer ${jwtForBranch}`);
      const verified = Bcrypt.compareSync(body.password, brachObj.password);
      if(verified) {
        let userDetails = await singleRecord({where: {user_id: brachObj.user_id}})
        brachObj.isBranch = true
        delete brachObj.password
        brachObj.isApproved = userDetails.isApproved
        res.send(brachObj)
        return;
      } else {
        res.status(400).json({message: "Password does not match"});
        return;
      }      
    }
    if(user.isActive === false || user.isActive === 0) {
      res.status(400).json({message: "User is not active please contact admin"})
      return
    }
    let jwt = await helper.jwtToken(user.user_id);
    res.setHeader("x-access-token", `Bearer ${jwt}`);
    const verified = Bcrypt.compareSync(body.password, user.password);
    if (verified) {
      if(user.user_type === USER_TYPE.admin ){
        let resp = {
          l_name: user.l_name,
          f_name: user.f_name,
          contact_no: user.contact_no,
          email:user.email
        }
        res.send(resp);
        return;
      }
      user = JSON.parse(JSON.stringify(user))
      delete user.password
      let date = new Date()
      await updateRecord({last_login: date}, {where: {user_id: user.user_id}})
      res.send(user);
      return;
    } else {
      res.status(400).json({message: "you have entered wrong password"});
    }
  } catch (error) {
    console.log({ error });
    res.status(500).json("Error: " + error);
  }
};
exports.forget = async (req, res) => {
  try {
    let body = req.body;
    let query = {
      where: {},
    };
    if (body.user_type === USER_TYPE.station_emp) {
      query.where.station_id = body.station_id;
    } else {
      delete query.where.station_id;
      query.where.email = body.email;
    }

    let userDetails = await singleRecord(query);
    if (!userDetails) {
      res.status(400).json({message: "Email not register"});
    }
    let randomNumber = await helper.createStationId();
    let newOtp = `${randomNumber}${userDetails.user_id}`;
    let object = {
      to: userDetails.email,
      subject: "welcome to yudget",
      text: `your one time password is  ${newOtp}`,
      //  html:"ddakusfdydbfjgdufgd"
    };
    let queryObject = {
      where: { user_id: userDetails.user_id },
    };
    let bodybject = {
      otp: newOtp,
    };
    // otp send in DB
    await updateRecord(bodybject, queryObject);
    await emailsend(object);

    res.send("OPT send your register Email address");
  } catch (error) {
    console.log({ error });
    res.status(500).json("Error: " + error);
  }
};


exports.resetPassword = async (req, res) => {
  try {
    let body = req.body;
    let query = {
      where: {
        otp: body.otp,
      },
    };
    let user = await singleRecord(query);
    if (!user) {
      res.status(400).json({message: "Wrong OTP!"});
      return;
    }
    if (user) {
      let hashPassword = await helper.createPassword(body.password);
      let bodyObject = {
        password: hashPassword,
        otp: null,
      };
      let queryObject = {
        where: {
          user_id: user.user_id,
        },
      };     
      await updateRecord(bodyObject, queryObject);
      res.send("password successfully changed");
      return;
    } else {
      res.status(400).json({message: "Wrong OTP!"});
    }
  } catch (error) {
    console.log({ error });
    res.status(500).json("Error: " + error);
  }
};

exports.changePassword = async (req, res) => {
    try {
        let id = req.userId
        let body = req.body
        let query = {
            where: {
                user_id: id
            }
        }
        let userDetail = await singleRecord(query)
        if(!userDetail) {
            res.status(400).json({message: 'User not exits'})
            return
        }
        // checking password is match
        let convertedPassword  = await helper.createPassword(body.current_password);
        let newPassword  = await helper.createPassword(body.password);
       

        const verified = Bcrypt.compareSync(body.current_password, userDetail.password);
        if(verified) {
            let bodybject = {
                password :newPassword 
            }
            let query = {
                where: {
                    user_id : req.userId
                }
            }
            await updateRecord(bodybject, query)
            res.send('Your password has been successfully changed')
            return
        } else {
            res.status(400).json({message: `Current password is wrong`})
            return
        }
  }  catch (error) {
    console.log({ error });
    res.status(500).json("Error: " + error);
  }
}
module.exports.updateProfile = async (req, res)=> {
  try {
   
    let id = req.userId
    let query = {
      where: {
        user_id: id
      }
    }
    let body = req.body
    if(body.password) {
      delete body.password
    }
    if(body.credit) {
      delete body.credit
    }
    let obj = await singleRecord(query)
    if(!obj) {
      res.status(400).json({message: 'User not exist'})
      return
    }   
    if (req.files && req.files.profile_pic){
      let proTime = new Date().getTime() / 1000;
      await fileUpload(req.files.profile_pic, `${proTime}profile`);
      body.profile_pic = `./images/${proTime}profile.jpg`;


      if(obj.profile_pic) {
        let path = obj.profile_pic.split('/')
        if (fs.existsSync(`./public/images/${path[2]}`)) fs.unlinkSync(`./public/images/${path[2]}`);
      }
    }
    if (req.files && req.files.vat_registration_certificate ){
      let vat = req.files.vat_registration_certificate
      let vatTime = new Date().getTime() / 1000;
      await fileUploadPdf(vat, `${vatTime}vat`);
      body.vat_registration_certificate = `./pdf/${vatTime}vat.pdf`;
      if(obj.vat_registration_certificate) {
        let path = obj.vat_registration_certificate.split('/')
        if (fs.existsSync(`./public/pdf/${path[2]}`)) fs.unlinkSync(`./public/pdf/${path[2]}`);
      }
    }
    if (req.files && req.files.company_logo ){
      let logo = req.files.company_logo
      let logoTime = new Date().getTime() / 1000;
      await fileUpload(logo, `${logoTime}logo`);
      body.company_logo = `./images/${logoTime}logo.jpg`;
      if(obj.company_logo) {
        let path = obj.company_logo.split('/')
        if (fs.existsSync(`./public/images/${path[2]}`)) fs.unlinkSync(`./public/images/${path[2]}`);
      }
    }
    if (req.files && req.files.commercial_registration_certificate){
      let path = req.files.commercial_registration_certificate
      let pathTime = new Date().getTime() / 1000;
      await fileUploadPdf(path, `${pathTime}commercial_registration_certificate`);
      body.commercial_registration_certificate = `./pdf/${pathTime}commercial_registration_certificate.pdf`;
      if(obj.commercial_registration_certificate) {
        let path = obj.commercial_registration_certificate.split('/')
        if (fs.existsSync(`./public/pdf/${path[2]}`)) fs.unlinkSync(`./public/pdf/${path[2]}`);
      }
     
    }  
    

    await updateRecord(body, query)
    res.send({message : "profile is updated"})

  } catch (error) {
    res.status(500).json(`Error ${error}`);
  }
}