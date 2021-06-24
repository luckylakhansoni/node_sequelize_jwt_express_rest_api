const dbConfig = require("../config/db.config.js");

const Sequelize = require("sequelize");
const sequelize = new Sequelize(dbConfig.DB, dbConfig.USER, dbConfig.PASSWORD, {
  host: dbConfig.HOST,
  dialect: dbConfig.dialect,

  pool: {
    max: dbConfig.pool.max,
    min: dbConfig.pool.min,
    acquire: dbConfig.pool.acquire,
    idle: dbConfig.pool.idle,
  },
});

const db = {};

db.Sequelize = Sequelize;
db.sequelize = sequelize;

db.user = require("./users.model.js")(sequelize, Sequelize);
db.country = require("./country.model.js")(sequelize, Sequelize);
db.state = require("./state.model.js")(sequelize, Sequelize);
db.city = require("./city.model.js")(sequelize, Sequelize);
db.district = require("./district.model")(sequelize, Sequelize);

db.contact = require("./contact.model")(sequelize, Sequelize);
db.car = require("./car.model")(sequelize, Sequelize);
db.branch = require("./branch.model")(sequelize, Sequelize);
db.transaction = require("./transaction.model")(sequelize, Sequelize);
db.solution = require("./solution.model")(sequelize, Sequelize);
db.company = require("./companies.model")(sequelize, Sequelize);
db.image = require("./image.model")(sequelize, Sequelize);
db.network = require("./network.model")(sequelize, Sequelize);
db.gasCompany = require("./company.model")(sequelize, Sequelize);
db.parnter = require("./partner.model")(sequelize, Sequelize);
db.about = require("./about.model")(sequelize, Sequelize);
db.price = require("./pricing.model")(sequelize, Sequelize);
db.home = require("./homepage.model")(sequelize, Sequelize);
db.privacy = require("./privacy.model")(sequelize, Sequelize);
db.getInTouch = require("./getInTouch.model")(sequelize, Sequelize);
db.notification = require("./notification.model")(sequelize, Sequelize);
db.fuelPrice = require("./fuel_price.model")(sequelize, Sequelize);
db.report = require("./report.model")(sequelize, Sequelize);
db.vatBill = require("./vat_bills.model")(sequelize, Sequelize);
db.bill = require("./bills.model")(sequelize, Sequelize);
db.brand = require("./brand.model")(sequelize, Sequelize);
db.carType = require("./car_type.model")(sequelize, Sequelize);
db.year = require("./year.model")(sequelize, Sequelize);
db.support = require("./support.model")(sequelize, Sequelize);
db.station_emp = require("./station_emp.model")(sequelize, Sequelize);
db.package = require("./package.model")(sequelize, Sequelize);
db.defaultFee = require("./default_fee.model")(sequelize, Sequelize);
db.adminTransaction = require("./admin-trasnaction.model")(sequelize, Sequelize);
db.invoice = require("./invoice.model")(sequelize, Sequelize);
db.payment = require("./payment.model")(sequelize, Sequelize);













//  getting branch object
db.car.hasOne(db.branch, {
  sourceKey: "branch_id",
  foreignKey: "branch_id",
  as: "BranchDeytails",
  constraints: false,
});
// getting car array
db.branch.hasMany(db.car, {
  sourceKey: "branch_id",
  foreignKey: "branch_id",
  as: "carDetails",
  constraints: false,
});

// getting user object from branch table 
db.branch.hasOne(db.user, {
  sourceKey: "user_id",
  foreignKey: "user_id",
  as: "userDetails",
  constraints: false,
});

// getting user object from car table 
db.car.hasOne(db.user, {
  sourceKey: "user_id",
  foreignKey: "user_id",
  as: "userDetails",
  constraints: false,
});
// city Data
db.district.hasMany(db.city, {
  sourceKey: "district_id",
  foreignKey: "district_id",
  as: "cityData",
  constraints: false,
});

db.branch.hasOne(db.city, {
  sourceKey: "city_id",
  foreignKey: "city_id",
  as: "cityData",
  constraints: false,
});

db.branch.hasOne(db.district, {
  sourceKey: "district_id",
  foreignKey: "district_id",
  as: "districtData",
  constraints: false,
});

db.car.hasOne(db.carType, {
  sourceKey: "car_type_id",
  foreignKey: "car_type_id",
  as: "carTypeDetails",
  constraints: false,
});

db.car.hasOne(db.year, {
  sourceKey: "year_id",
  foreignKey: "year_id",
  as: "yearDetails",
  constraints: false,
});
db.car.hasOne(db.brand, {
  sourceKey: "brand_id",
  foreignKey: "brand_id",
  as: "brandDetails",
  constraints: false,
});

db.car.hasOne(db.fuelPrice, {
  sourceKey: "fuel_type_id",
  foreignKey: "fuel_price_id",
  as: "fuelTypeDetails",
  constraints: false,
});
db.station_emp.hasOne(db.gasCompany, {
  sourceKey: "company_id",
  foreignKey: "company_id",
  as: "companyDetails",
  constraints: false,
});


db.support.hasOne(db.station_emp, {
  sourceKey: "user_id",
  foreignKey: "station_id",
  as: "station_emp_data",
  constraints: false,
});

db.transaction.hasOne(db.car, {
  sourceKey: "car_plate",
  foreignKey: "car_plate",
  as: "carDetails",
  constraints: false,
});

db.network.hasOne(db.gasCompany, {
  sourceKey: "company_id",
  foreignKey: "company_id",
  as: "gasStationDetails",
  constraints: false,
});

db.network.hasOne(db.station_emp, {
  sourceKey: "station_id",
  foreignKey: "station_id",
  as: "stationEmpDetails",
  constraints: false,
});
db.gasCompany.hasMany(db.station_emp, {
  sourceKey: "company_id",
  foreignKey: "company_id",
  as: "stationDetail",
  constraints: false,
})





module.exports = db;
