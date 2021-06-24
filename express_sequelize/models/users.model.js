const {USER_TYPE} = require('../utils/constant')
module.exports = (sequelize, DataTypes) => {
    const User = sequelize.define("User", {
        user_id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true
        },
        f_name: DataTypes.STRING,
        l_name: DataTypes.STRING,
        cuntry_code: DataTypes.INTEGER,
        company_name: DataTypes.STRING,
        company_address: DataTypes.STRING,
        company_type: DataTypes.STRING,
        company_reg_no: DataTypes.STRING,
        vat_no: DataTypes.STRING,
        address1: DataTypes.STRING,
        address2: DataTypes.STRING,
        company_phone_no: DataTypes.STRING,
        company_email: DataTypes.STRING,       
        otp: DataTypes.STRING,
        email: {
            type: DataTypes.STRING,
            allowNull: false,
            validate: {
              isEmail:true
            },
            unique: {
                args: true,
                msg: 'Email address already in use!'
            }
          },
          password: DataTypes.STRING,
          station_id: {
            type: DataTypes.STRING,
            unique: {
                args: true,
                msg: 'some is already use!'
            }
        },
        company_name: DataTypes.STRING,
        contact_no: DataTypes.STRING,
        verification_code: DataTypes.STRING,
        user_type:DataTypes.ENUM(USER_TYPE.user, USER_TYPE.admin, USER_TYPE.station_emp),
        credit:DataTypes.DECIMAL(10,2),
        profile_pic: DataTypes.STRING,
        company_logo: DataTypes.STRING,
        commercial_registration_certificate: DataTypes.STRING,
        vat_registration_certificate: DataTypes.STRING,
        credit_wit_charges:{
            type: DataTypes.DECIMAL(10,2),
            default: 0
        }, 
        commission:{
            type: DataTypes.DECIMAL(10,2),
            default: 0
        },       
        isActive:{
            type: DataTypes.BOOLEAN,
            defaultValue: true
         },
         last_login: DataTypes.DATE,
         isApproved:{
            type: DataTypes.BOOLEAN,
            defaultValue: false
         }
    }, {
        timestamps: true,
        deletedAt: 'deletedAt',
        paranoid: true,
        tableName: "users"
    });
    sequelize.sync({
        force: false,
        logging: false,
        alter: true
    });
   
    return User;
  };