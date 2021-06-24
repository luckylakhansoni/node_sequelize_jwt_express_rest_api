const jwt = require("jsonwebtoken");
const db = require("../models");
const User = db.user;
const { JWT, USER_TYPE } = require("../utils/constant");
const getAuthToken = (req, res, next) => {
  if (
    req.headers.authorization &&
    req.headers.authorization.split(" ")[0] === "Bearer"
  ) {
    req.authToken = req.headers.authorization.split(" ")[1];
  } else {
    req.authToken = null;
  }
  next();
};
exports.isAuthenticate = async (req, res, next) => {
  getAuthToken(req, res, async () => {
    try {
      let decoded = jwt.verify(req.authToken, JWT.tokenString);

      if (decoded.user_id) {
        let userDetails = await User.findOne({
          where: {
            user_id: decoded.user_id,
          },
        });
        if (userDetails) {
          req.userId = userDetails.user_id;
          req.userType = userDetails.user_type;
          req.isActive = userDetails.user_type;

          return next();
        } else {
          return res
            .status(401)
            .json({ message: "You are not authorized to make this request" });
        }
      } else if (decoded.station_id) {
        let stationDetails = await db.station_emp.findOne({
          where: {
            station_id: decoded.station_id,
          },
        });
        if (stationDetails) {
          req.userId = stationDetails.station_id;
          return next();
        } else {
          return res
            .status(401)
            .json({ message: "You are not authorized to make this request" });
        }
      } else if (decoded.branch_id) {
        let branchDetails = await db.branch.findOne({
          where: {
            branch_id: decoded.branch_id,
          },
        });
        if (branchDetails) {
          req.branch_id = branchDetails.branch_id;
          req.isBranch = true,
          req.userId= branchDetails.user_id
          req.isActive = branchDetails.isActive


          return next();
        } else {
          return res
            .status(401)
            .json({ message: "You are not authorized to make this request" });
        }
      }else {
        return res
          .status(401)
          .json({ message: "You are not authorized to make this request" });
      }
    } catch (error) {
      console.log(error);
      return res
        .status(401)
        .json({ message: "You are not authorized to make this request" });
    }
  });
};
exports.isStationEmp = async (req, res, next) => {
  try {
    if (req.userType === USER_TYPE.station_emp) {
      return next();
    } else {
      return res
        .status(401)
        .json({ message: "You are not station employee to make this request" });
    }
  } catch (error) {
    return res
      .status(401)
      .json({ message: "You are not station employee to make this request" });
  }
};

exports.isAdmin = async (req, res, next) => {
  try {
    if (req.userType === USER_TYPE.admin) {
      return next();
    } else {
      return res
        .status(401)
        .json({ message: "You are not Admin to make this request" });
    }
  } catch (error) {
    return res
      .status(401)
      .json({ message: "You are not Admin to make this request" });
  }
};

exports.isUser = async (req, res, next) => {
  try {
    if (req.userType === USER_TYPE.user) {
      return next();
    } else {
      return res
        .status(401)
        .json({ message: "You are not User to make this request" });
    }
  } catch (error) {
    return res
      .status(401)
      .json({ message: "You are not User to make this request" });
  }
};
exports.isStationEmp = async (req, res, next) => {
  try {
    if (req.userType === USER_TYPE.station_emp) {
      return next();
    } else {
      return res
        .status(401)
        .json({ message: "You are not Station emp to make this request" });
    }
  } catch (error) {
    return res
      .status(401)
      .json({ message: "You are not Station emp to make this request" });
  }
};

exports.isActiveCompany = async (req, res, next) => {
  try {
    if (req.isActive === 0 || req.isActive === false) {
      return res
        .status(401)
        .json({ message: "Your Account is deactived by admin" });

    } else {
      return next();
      
    }
  } catch (error) {
    return res
      .status(401)
      .json({ message: "You are not Station emp to make this request" });
  }
};
