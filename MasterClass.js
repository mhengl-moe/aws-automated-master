/*!
     * Copyright 2017-2017 Mutual of Enumclaw. All Rights Reserved.
     * License: Public
*/ 

//Mutual of Enumclaw 
//
//Matthew Hengl and Jocelyn Borovich - 2019 :) :)
//
//Class file containing many functions used throughout the main files to perform specific jobs.
//All functions perform a specific task and none are built for an individual file.

const AWS = require('aws-sdk'); 
AWS.config.update({region: process.env.region});
// const sns = new AWS.SNS();
const ses = new AWS.SES();
const dynamodb = new AWS.DynamoDB();

let reason = { Reason: 'Reason not specified'};
let subject = { Subject: '¯\\_(ツ)_/¯' };
let path = { p: '' };
let stopper = { id: '' };
let dbStopper = {};

//console.log = (message, attachment) => {};
setSes = (value, funct) => {
   ses[value] = funct;
};

class Master {

   //**********************************************************************************************
   //Checks the event log for previous errors
   /**/errorInLog(event) {
      if (event.detail.errorCode) {
         //console.log(`************There was an error in the event log (code: "${event.detail.errorCode}")************`);
         path.p += `\nError in log ${event.detail.errorCode}`;
         return true;
      }
      path.p += `\nNo Error in log`;
      return false;
   }

   
   //**********************************************************************************************
   //Checks to see if there is any specific properties of the resource before running the function (testing only)
   /**/checkKeyUser(event, resourceName){
      //checking event.detail.responseElements.policy.policyName
      if(event.detail.userIdentity.principalId.includes(`${process.env.emailForTesting}`) ||
      event.detail.userIdentity.arn.includes(`${process.env.serverlessInfo}`) ||
      event.detail.requestParameters[resourceName].includes("@@@")) {

         //console.log("Found the key!~~~~");
         path.p += '\nKey found!';
         return true;
      }
      //console.log("*************Did not find key, ending program*************");
      path.p += '\nKey Not Found';
      return false;
   }
   
   
   //**********************************************************************************************
   //Checks to see if the event coming from DynamoDB.
   /**/checkDynamoDB(event){
      if(event.Records){
         //console.log("Event is DynamoDB!~~~~~~~~~~~");
         path.p += '\nEvent is DynamoDB';
         return true;
      }
      //console.log("Event is NOT DynamoDB!~~~~~~~~~~~~");
      path.p += '\nEvent is Not DynamoDB';
      return false;
   }
   
   
   //**********************************************************************************************
   //Converts the information coming from DynamoDB into an actual JSON file for js to read
   /**/dbConverter(event){
      let info = event.Records[0].dynamodb.OldImage;
      var unmarshalled = AWS.DynamoDB.Converter.unmarshall(info);
      return unmarshalled;
   }
   
   
   //**********************************************************************************************
   //checks if the event was from the function itself
   /**/selfInvoked(event) {
      if (event.detail.userIdentity.arn.includes(process.env.name)) {
         //console.log('****************************Self invoked****************************');
         path.p += '\nSelf Invoked';
         return true;
      }
      path.p += '\nNot Self Invoked';
      return false;
   }
   
   
   //**********************************************************************************************
   //Gets the entity that performed the action and returns it.
   /**/getEntity(event){
      let id = event.detail.userIdentity.principalId;
      
      if (id.includes(':') && !id.includes('@')) {
         let index = id.indexOf(":") + 1;
         return `${id.substring(index)} --Likely a lambda function`;
      } else if (id.includes('@')) {
         let index = id.indexOf(":") + 1;
         return id.substring(index);
      } else {
         return `${event.detail.userIdentity.userName}  --Launched through serverless/TFS`;
      }
   }
   
   
   //**********************************************************************************************
   //Validates the event log (determines whether it comes from console, console being invalid)
   /**/invalid(event){
      
      //checks if self invoked
      if (this.snd()) {   
         //console.log('****************Performed in Sandbox so event is valid****************');
         path.p += '\nPerformed in snd so event is valid';
         return false;
         
      } else if (this.isConsole(event)) {
         
         //console.log('Performed through console and in dev/prd so event log is invalid-----------------------');
         path.p += '\nPerformed through console and in dev/prd so event log is invalid';
         return true;
      }
      //console.log('****************Performed through Serverless/TFS so event is valid****************');
      path.p += '\nPerformed through Serverless/TFS so event is valid';
      return false;
   }
   
   //**********************************************************************************************
   //Function used to check to see if the event is coming from console
   /**/isConsole(event){
      if((event.detail.userIdentity.sessionContext.sessionIssuer) ||
      (event.detail.userAgent != 'cloudformation.amazonaws.com')){
         path.p += '\nEvent is created through console';
         return true;
      }
      path.p += '\nEvent was not created through console';
      return false;
   }


   //**********************************************************************************************
   //Creates the HTML for the user that performed the action depending on the event type and returns it
  /**/getHtml(event, results, type) {

   console.log(results);
   
   //This is an object that is created to house all of the changing variables for the HTML template
   let myHTML = {
      env: process.env.environment,
      message: this.structureMessage(results),
      header: `Your AWS stuff was remediated...</br>`,
      description: ``,
      howToFixMessage: `Please add the correct tags to "${results.ResourceName}" to prevent modification (${process.env.tag1} and ${process.env.tag2}).`,
      colorHeader: ``,
      spaces: `</br></br>`,
      shrugg: `¯\\_(ツ)_/¯`
   };
   //If statments being used to see what is needed to go into the formatting for the HTML template
   //If the results has a killtime or not.
   if(results.KillTime){

      path.p += '\nDynamoDB event HTML';
      myHTML.header = `Your ${type} has been modified...</br>${myHTML.shrugg}`;
      myHTML.description = `Your ${type} "${results.ResourceName}" has been modified and all its attachments have been remediated by AWS Automated Security.`;
      myHTML.howToFixMessage = `Next time, please be sure to add the proper tags to your ${type} (${process.env.tag1} and ${process.env.tag2}).`;

   } else if (!results.Response) {
      path.p += '\nResourceName being added to DynamoDB HTML';
      subject.Subject = 'You forgot your tags...¯\\_(ツ)_/¯'; 
      let days = this.undoEpoch(this.createTTL(event));
      let s = 's';
      if (days == 1) {
         s = '';
      }
      myHTML.header = `Ahhhh Snap! You forgot your tags...</br>${myHTML.shrugg}`;
      myHTML.description = `Your ${type} "${results.ResourceName}" has been archived for modified in ${days} day${s} by AWS Automated Security.`;

   //If a resource was modified and cannot be recreated
   } else if (results.Response == 'Remediation could not be performed'){
        
      path.p += '\nResourceName being improperly modified HTML';
      subject.Subject = `Improper Modification`;
      myHTML.colorHeader = `style="color:red"`;
      myHTML.header = `"${results.ResourceName}" was modified...`;
      myHTML.description = `You have improperly modified the ${type} "${results.ResourceName}".`;
      myHTML.howToFixMessage = `Next time, please remove through Serverless or TFS when deleting resources.`;

   //If the event was the remediation of a creation of a new policy version
   } else if (results['Reset Default Version']){

      path.p += '\nDefaul Policy Version HTML';
      subject.Subject = `A default policy version has been reset. ${myHTML.shrugg}`;
      myHTML.colorHeader = `style = 'color:red'`;
      myHTML.header = `The policy version ${results["Old Default Version"]} has been reset... ${myHTML.shrugg}`;
      myHTML.description = `The policy "${results.ResourceName}" has been set to ${results['Reset Default Version']} by AWS Automated Security.`;
      myHTML.howToFixMessage = `Next time, please deploy through Serverless or TFS when creating new policy versions.`;

   //Default notification  
   } else {

      path.p += '\nUser Warning HTML';
      subject.Subject = 'Your AWS stuff was remediated...¯\\_(ツ)_/¯';
      myHTML.description = `The ${type} "${results.ResourceName}" has been remediated by AWS Automated Security.`;
      if (results.Reason == 'Improper Launch') {
         myHTML.howToFixMessage = `Next time, please deploy through Serverless or TFS when working in ${myHTML.env} to prevent remediation`;
      }
   }


   return `
       <html>
           <body style="width:100%">
               <div style="width:100%">
                   <h1 ${myHTML.colorHeader}>
                       ${myHTML.header}
                   </h1>
                   <p style = 'color:red'>${myHTML.description}</p>
                   <p>${myHTML.howToFixMessage}</p>
                   <p>${myHTML.spaces}${myHTML.message}</p>
                   <div style="text-align:center">
                       <font></br></br></br><b>Have a wonderful day!</b></font>
                   </div>
                   <div style="text-align:center">
                       <font>${myHTML.shrugg}</font>
                   </div>
               </div>
           </body>
       </html>
   `;
  }

  
  //**********************************************************************************************
  //Creates the HTML for an email to security depending on the event type and returns it
  /**/getHtmlSecurity(event, results, type){

   let myHTML = {
      env: process.env.environment,
      message: this.structureMessage(results),
      header: `AWS stuff was remediated in ${this.env}...</br>`,
      description: '',
      colorHeader: ``,
      spaces: `</br>`
   };

   if (results.KillTime) {

      path.p += '\nDynamoDB event HTML';
      subject.Subject = `A ${type} was auto-modified in ${myHTML.env}`;
      myHTML.header = `A ${type} has been auto-modified in ${myHTML.env}...</br>`;
      myHTML.description = `A ${type} "${results.ResourceName}" has been modified and all its attachments have been remediated by AWS automated security.`;
      
   //If the event is just the creation of a resource with incorrect tags
   } else if (!results.Response) {

      path.p += '\nResourceName being added to DynamoDB HTML';
      myHTML.header = `A resource was created in ${myHTML.env} without the proper tags.</br>`;
      let days = this.undoEpoch(this.createTTL(event));
      let s = 's';
      if (days == 1) {
         s = ''; 
      }
      myHTML.description = `A ${type} "${results.ResourceName}" has been archived for modification in ${days} day${s} by AWS Automated Security. The correct tags need to be added to "${results.Resource}" to prevent deletion (${process.env.tag1} and ${process.env.tag2}).`;
      myHTML.spaces = '</br></br>';
      
   //If a resource was modified and cannot be recreated
   } else if (results.Response == 'Remediation could not be performed'){

      path.p += '\nResourceName being improperly modified HTML';
      subject.Subject = `Improper Modification in ${myHTML.env}`;
      myHTML.colorHeader = `style="color:red"`;
      myHTML.header = `"${results.ResourceName}" was modified through ${myHTML.env} console...`;
      myHTML.description = `The ${type} "${results.ResourceName}" has been modified by "${results['Entity Responsible']}" through ${myHTML.env} console and could not be remediated by AWS Automated Security.`;

   //If the event was the remediation of a creation of a new policy version   
   } else if(results['Reset Default Version']){

      path.p += '\nDefaul Policy Version HTML';
      subject.Subject = `A default policy version has been auto-reset in ${myHTML.env}.`;
      myHTML.colorHeader = `style = 'color:red'`;
      myHTML.header = `The policy version ${results["Old Default Version"]} was improperly set to default through ${myHTML.env} console...`;
      myHTML.description = `The policy "${results.ResourceName}" has been set to ${results['Reset Default Version']} by AWS Automated Security.`;

   //Default notification
   } else {

      path.p += '\nUser Warning HTML';
      subject.Subject = `An AWS resource was remediated in ${myHTML.env}.`;
      myHTML.description = `The ${type} "${results.ResourceName}" has been remediated by AWS Automated Security.`;
   }

   //returns the html template with the defined variables inside
   return `
   <html>
       <body style="width:100%">
           <div style="width:100%">
               <h1 ${myHTML.colorHeader}>${myHTML.header}</h1>
               <p style = 'color:red'>${myHTML.description}</p>
               <p>${myHTML.spaces}${myHTML.message}${myHTML.spaces}</p>
               <div style="text-align:center">
               <a href = https://giphy.com/gifs/maury-maury-face-xT1XGWbE0XiBDX2T8Q/fullscreen>uuuhhh oooh....</a>
               <font></br></br></br><b>Have a wonderful day!</b></font>
               </div>
           </div>
       </body>
   </html>`;
  }
  
  //**********************************************************************************************
  //Builds the results object
  /**/getResults(event, property) {
     
     return {
         Action: event.detail.eventName,
         Environment: process.env.environment,
         "Entity Responsible": this.getEntity(event),
         ...property
     };
  }

     //**********************************************************************************************
  //Returns a cloudwatch event given a dynamo event with specified requestParameters
  /**/translateDynamoToCloudwatchEvent(event, requestParameters){
         return {
            detail: {
               userIdentity: {
                  principalId: `ASDFGHJAKKHGFG:${event.Records[0].dynamodb.OldImage['Entity Responsible'].S}`
               },
               eventName: '',
               requestParameters: {
                  ...requestParameters
               }
            }
         };
   }
  
  //**********************************************************************************************
  //Sends an email to the user
  //notifyUser
  async notifyUser(event, results, type){

     const sender = `${process.env.sender}`;
     let recipient = '';
     let body_html = '';

     if (results['Entity Responsible'].includes('@') && event.Recusion == undefined) {
        recipient = results['Entity Responsible'];
        //console.log("Sending to user! ~~~~~~~~~~~~~~~~~~");
        path.p += '\nSending to user';
        body_html = this.getHtml(event, results, type);
        path.p += '\nGot HTML to send to user';

        if(results.Response == "Remediation could not be performed"){
           event.Recusion = true;
           path.p += '\nNeeds to send to security';
           await this.notifyUser(event, results, type);
        }
     } else {
        path.p += '\nSending to security as well';
        //console.log("Sending to security! ~~~~~~~~~~~~~~~~~~");
        recipient = `${process.env.emailForTesting}`;
        body_html = this.getHtmlSecurity(event, results, type);
     }
     var params = {
        Source: sender,
        Destination: {
           ToAddresses: [
           recipient
           ]
        },
        Message: {
           Subject: {
              Data: subject.Subject
           },
           Body: {
              Text: {
                 Data: ''
              },
              Html: {
                 Data: body_html
              }
           }
        }
     };
      console.log('sendEmail');
      console.log(process.env.run);
      if(process.env.run == 'false'){
         await setSes('sendEmail', (params) => {
            console.log('Overriding SES');
            console.log(results);
            let html = params.Message.Body.Html.Data;
            console.log(html);
            return {promise: () => {}};
         });
         await ses.sendEmail(params).promise();
      }
      path.p += `\nEmail sent to ${recipient}`;
      //console.log(`**************Message sent to ${recipient}**************\n\n`);
  }

  

   
   //**********************************************************************************************
   //Helper function that structures the email
   //structureMessage
   structureMessage(results) {

      //Reorders the results properties for the dynamo event to the baseline order so the email structures correctly.  
      if(results.KillTime) {
         results = {
            Action: results.Action,
            "Entity Responsible": results['Entity Responsible'],
            Environment: process.env.environment,
            ResourceName: results.ResourceName,
            ResourceType: results.ResourceType,
            Reason: results.Reason
         };
      }
      
      results = Object.entries(results);

      //converts the given results information into an html display
      const rows = results.map((pair) => { 
         return `<tr><td style="padding: 5px "><b>${pair[0]}:</b></td><td>${pair[1]}</td></tr>`;
      }).join('');
      
      let message = `
      <table style="width:100%"> 
         ${rows}
      </table>`;
            
      return message;
   }

   
   //**********************************************************************************************
   //functions that return whether or not the event is in the specific environment.
   /**/snd() {
      return process.env.environment == 'snd';
   }
   
   /**/dev(event) {
      let num = this.getNumber(event);
      return num == `${process.env.devNum1}` || num == `${process.env.devNum2}`;
   }
   
   /**/prd(event) {
      let num = this.getNumber(event);
      return num == `${process.env.prdNum1}` || num == `${process.env.prdNum2}`;
   }
   
   //gets the number that corresponds the environment for the given event.
   /**/getNumber(event) {
      return  event.detail.userIdentity.accountId;
   }
   
   
   //**********************************************************************************************
   //Returns if the given resource is in the table or not.
   //checkTable
   async checkTable(ResourceName, ResourceType){
      //console.log("Checking table for item.");
      path.p += '\nChecking table for item';
      let params = {
         Key: { 
            "ResourceName": {
               S: ResourceName
            },
            "ResourceType":{
               S: ResourceType
            }
         },
         TableName: `remediation-db-table-${process.env.environment}-ShadowRealm`
      };
      let pulledItem = await dynamodb.getItem(params).promise();
      if(pulledItem.Item){
         //console.log(`**************Found ${ResourceName} in the table, ending program**************`);
         path.p += `\nFound ${ResourceName} in the table`;
         return true;
      }
      //console.log(`Did not find ${ResourceName}-------`);
      path.p += `\nDid not find ${ResourceName} in table`;
      return false;
   }
   
   
   //**********************************************************************************************
   //Returns the amount of time before the item is deleted from the table depending on it's environment
   /**/createTTL(event) {
      if(this.snd()) {
         
         return this.getTime(.002);  //CHANGE TO 30 DAYS WHEN GUARD RAILS ARE OFF
         
      } else if(this.dev(event)) {
         
         return this.getTime(1);
      }
      
      return this.getTime(7);
   }
   
   //helper function that translates the current time into epoch based on days to wait
   /**/getTime(days) {
      let time = new Date().getTime() / 1000 + days * 86400;
      return time + '';
   }
   
   //returns the number of days that the given epoch time represents
   /**/undoEpoch(time) {
      let days = (time - new Date().getTime() / 1000) / 86400;
      return Math.ceil(days);
   }
   
   
   //**********************************************************************************************
   //checks if the given service has all the right tags, returns true if it does.
   /**/tagVerification(tags){
      console.log(tags);
      //Stores only unique values for counting the tags
      let keySet = new Set();

      //Checks for the two required
      tags.forEach((object) => {
         const key = object.Key.trim();
         if (key == `${process.env.tag2}` || key == `${process.env.tag1}`) {
            keySet.add(key);
         }
      });

      if (keySet.size == 2) {
         //console.log('**************Tag verification succeeded, ending program**************');
         path.p += '\nTagVerification successful, resource has the proper tags';
         return true;
      }
      reason.Reason = 'Improper Tags';
      //console.log('Required tags not found-----------------');
      path.p += '\nTagVerification failed';
      return false;
   }
   
   
   //**********************************************************************************************
   //Returns the required params for adding tags to the resource
   /**/getParamsForAddingTags(event, params, tagName) {
      
      let value = '';
      
      if (tagName == 'Environment') {
         value = process.env.environment;
      } else {
         value = this.getEntity(event);
      }
      
      return {
         Tags: [
         {
            Key: tagName,
            Value: value
         }
         ],
         ...params
      };
   }
   
   
   //**********************************************************************************************
   //checks if the the specified tag needs to be added. Returns true if it does.
   /**/needsTag(tags, tagName) {
      if (tags.find((object) => {
         return object.Key.trim() == tagName;
      }) == undefined) {
         //console.log(`no ${tagName} found-------------`);
         path.p += `\nNo ${tagName} found`;
         return true;
      }
      //console.log(`${tagName} found-----------`);
      path.p += `\n${tagName} found`;
      return false;
   }
   
   
   //**********************************************************************************************
   //Adds the given resource to the dynamodb table
   //putItemInTable
   async putItemInTable(event, ResourceType, ResourceName) {

      //Checks to see if the resource is already in the table to prevent restarting the TTL and sending multiple emails
      if(await this.checkTable(ResourceName, ResourceType)) {
         return;
      }
      
      //Builds the params to add to the dynamodb table
      var params = {
         TableName: `remediation-db-table-${process.env.environment}-ShadowRealm`,
         Item: {
            'Action': { S: event.detail.eventName },
            'ResourceType': { S: ResourceType },
            'ResourceName': { S: ResourceName },
            'Entity Responsible': { S: await this.getEntity(event) },
            'KillTime': { N: this.createTTL(event) },
            'Reason': {S: reason.Reason}
         }
      };

      //Adds to dynamodb table with TTL
      //console.log('Adding to table--------');
      await dynamodb.putItem(params).promise();
      path.p += '\nResource added to table';
      await this.notifyUser(event, await this.getResults(event, { ResourceName: ResourceName, ResourceType: ResourceType,  Reason: reason.Reason}), ResourceType);
   }

   //**********************************************************************************************
   //Function to turn all instances of the snd account id into the dev account id
   /**/devTest(event){
      console.log('Changing the account info to dev');
      if(process.env.testEnv == 'dev'){
         event.detail.userIdentity.accountId = process.env.devNum2;
         process.env.environment = 'dev';
         console.log('Changed the account info to dev');
      }
      console.log(event);
      return event;
   };
   
   //**********************************************************************************************
   //overrides the publish property/function of sns (only for jest testing)
   /**/setSns(value) {
      sns.publish = value;
   }
   
   //overrides the sendEmail property/function of ses (only for jest testing)
   /**/setSes(value) {
      ses.sendEmail = value;
   }

   //overrides the putItem property/function of dynamodb (only for jest testing)
   /**/setDynamo(value) {
      dynamodb.putItem = value;
   }

   setTable(value) {
      dynamodb.getItem = value;
   }
}


module.exports.path = path;
module.exports.stopper = stopper;
module.exports.dbStopper = dbStopper;
exports.handler = Master;

//Created by Matthew Hengl and Jocelyn Borovich. Ur fav 2019 interns!! :) :)
