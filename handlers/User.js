const jwt = require('jwt-simple');
const moment = require('moment');

const Cognito = require('../services/Cognito');
const cognito = new Cognito();

const config = require('../configs/Cognito');
console.log('lambda loaded config', config);

/*
|--------------------------------------------------------------------------
| AWS invokes this method to process requests
|--------------------------------------------------------------------------
*/
exports.handler  = async function(event) {
  // /auth/{operation}
  const operation = event.pathParameters.operation;
  const payload = JSON.parse(event.body);
  let data;
  if(operation === 'signup') {
    console.log('payload', payload);
    try {
      data = await cognito.signUp(payload.name, payload.email, payload.password);
    } catch (e) {
      console.log('Error', e);
    }

  }

  console.log("Out", data);
  return data;
};