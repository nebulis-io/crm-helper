import * as awsSDK from "aws-sdk";
import { v4 } from 'uuid';
import jwt from "jsonwebtoken";


export interface ICRUDFunc {
    get(event: any, tableName: any, keys: string[]): any;
    post(event: any, check_func: (obj: any) => boolean, tableName: any): any;
    del(event: any, tableName: any): any;
    put(event: any, check_func: (obj: any) => boolean, tableName: any): any;
}

export interface IClient {
    last_name: string;
    first_name: string;
    email: string;
    id: string;
}
export interface IMission {
    mission_name: string;
    client: string;
    documents: string[];
}
export interface IDocument {
    id: string;
    file_name: string;
}

/**
 * http codes functions: to avoid writing a code manually each time it's needed
 */
const code_200 = (res: any = { message: "ok" }, headers: any = {}) => {
    return {
        statusCode: 200,
        body: JSON.stringify(res),
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Expose-Headers": "X-Total-Count",
            ...headers
        }
    };
}

const code_400 = (res: any = { error: "bad request" }) => {
    return {
        statusCode: 400,
        body: JSON.stringify(res),
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Expose-Headers": "X-Total-Count"
        }
    };
}

const code_401 = (res: any = { error: "unauthorized" }) => {
    return {
        statusCode: 401,
        body: JSON.stringify(res),
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Expose-Headers": "X-Total-Count"
        }
    };
}

const code_403 = (res: any = { error: "forbidden" }) => {
    return {
        statusCode: 403,
        body: JSON.stringify(res),
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Expose-Headers": "X-Total-Count"
        }
    };
}

const code_404 = (res: any = { error: "not found" }) => {
    return {
        statusCode: 404,
        body: JSON.stringify(res),
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Expose-Headers": "X-Total-Count"
        }
    };
}

const code_500 = (res: any = { error: "could not process the request" }) => {
    return {
        statusCode: 500,
        body: JSON.stringify(res),
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Expose-Headers": "X-Total-Count"
        }
    };
}

export const clientDyn = new awsSDK.DynamoDB.DocumentClient();

/**
 * helper class to avoid exporting each function manually
 */
export default class helper {
    code_200: (res?: any, headers?: any) => { statusCode: number; body: string; headers: any; };
    code_400: (res?: any) => { statusCode: number; body: string; headers: { "Access-Control-Allow-Origin": string; "Access-Control-Allow-Methods": string; "Access-Control-Allow-Headers": string; "Access-Control-Expose-Headers": string; }; };
    code_401: (res?: any) => { statusCode: number; body: string; headers: { "Access-Control-Allow-Origin": string; "Access-Control-Allow-Methods": string; "Access-Control-Allow-Headers": string; "Access-Control-Expose-Headers": string; }; };
    code_403: (res?: any) => { statusCode: number; body: string; headers: { "Access-Control-Allow-Origin": string; "Access-Control-Allow-Methods": string; "Access-Control-Allow-Headers": string; "Access-Control-Expose-Headers": string; }; };
    code_404: (res?: any) => { statusCode: number; body: string; headers: { "Access-Control-Allow-Origin": string; "Access-Control-Allow-Methods": string; "Access-Control-Allow-Headers": string; "Access-Control-Expose-Headers": string; }; };
    code_500: (res?: any) => { statusCode: number; body: string; headers: { "Access-Control-Allow-Origin": string; "Access-Control-Allow-Methods": string; "Access-Control-Allow-Headers": string; "Access-Control-Expose-Headers": string; }; };
    USER_TABLE_NAME: string;   //table containing the users for the auth part of this package
    config: { secret: string; }; //secret for the token gen
    auth_roles: { roles: any; }; // object containing the roles defined for the auth check

    constructor(USER_TABLE_NAME: string, CONFIG: string, AUTH_ROLES: string) {
        this.code_200 = code_200;
        this.code_400 = code_400;
        this.code_401 = code_401;
        this.code_403 = code_403;
        this.code_404 = code_404;
        this.code_500 = code_500;
        this.USER_TABLE_NAME = USER_TABLE_NAME;
        this.config = JSON.parse(CONFIG); //parsing because it's a process.env variable
        this.auth_roles = JSON.parse(AUTH_ROLES); //parsing because the auth roles are passed via process.env so it must be a string

        /* binding to this to avoid fuckery*/

        this.check = this.check.bind(this);
        this.check_id_in_table = this.check_id_in_table.bind(this);
        this.get_table = this.get_table.bind(this);
        this.get_element_by_id = this.get_element_by_id.bind(this);
        this.get = this.get.bind(this);
        this.post = this.post.bind(this);
        this.del = this.del.bind(this);
        this.put = this.put.bind(this);
        this.basic_crud_handler = this.basic_crud_handler.bind(this);
        this.base_handler = this.base_handler.bind(this);
        this.auth = this.auth.bind(this);
        this.check_bearer_struct = this.check_bearer_struct.bind(this);
        this.get_token = this.get_token.bind(this);
        this.check_auth = this.check_auth.bind(this);
        this.isAllowed = this.isAllowed.bind(this);

    }
    /**
     * part for making API logic creation easier
     */

    /**
     * generic function to check if all the properties do exist.
     * returns a boolean, true if each property does exist, false otherwise
     * @param arr an array of string that contains the properties to check
     * @param obj the object to check
     */
    check(arr: string[], obj: any) {
        console.log("obj", obj);
        for (let key of arr) {
            if (!(obj.hasOwnProperty(key))) {
                console.log("not existing key");
                return false;
            }
            if (obj[key] == null) {
                console.log("null object");
                return false;
            }

            if (typeof obj[key] == "string" && obj[key].length == 0) {
                console.log("empty string");
                return false;
            }
        }

        return true;
    }

    /**
     * generic function to check if an id is existing in a table
     * @param id the id to check
     * @param table the table to check in
     */
    async check_id_in_table(id: string, table: any) {
        const res = await clientDyn.scan({
            TableName: table.name.get(),
            AttributesToGet: ["id"],
        }).promise().then(result => result.Items?.map(item => item.id));
        return res!.includes(id);
    }

    /**
     * generic function to get all the records attributes
     * @param tableName the table to get all the records
     * @param keys attributes of the records: if the array is empty, 
     * it will get all the attributes of the records
     */
    async get_table(tableName: any, keys: string[] = []) {

        const table_data = (keys.length > 0) ? { TableName: tableName, AttributesToGet: keys } : { TableName: tableName };

        const res = await clientDyn.scan(table_data).promise().then((result: any) => result.Items);
        return res;
    }

    /**
     * generic function to get an element by its id
     * @param id the id of the record to get
     * @param tableName the table to look in
     * @param keys the attributes to get, an empty array will get all the attributes
     */
    async get_element_by_id(id: string, tableName: any, keys: string[] = []) {

        if (!this.check_id_in_table(id, tableName)) {
            return null;
        }
        const table_data = (keys.length > 0) ?
            {
                TableName: tableName,
                AttributesToGet: keys,
                Key: {
                    id: id
                }
            } :
            {
                TableName: tableName,
                Key: {
                    id: id
                }
            };


        const res = await clientDyn.get(table_data).promise().then(result => result.Item);

        return res;
    }

    /**
     * generic function used to process GET requests from the endpoint
     * @param event the event sent by APIGATEWAY
     * @param tableName the table to interact with
     * @param keys attributes of the record to get for the item corresponding to the id in the event
     */
    async get(event: any, tableName: any, keys: string[] = []) {

        if (event.pathParameters != null) {
            if (event.pathParameters.hasOwnProperty("id") && event.pathParameters.id != null) {
                const id = event.pathParameters.id;
                const res = await this.get_element_by_id(id, tableName, keys);
                if (res == null) {
                    return code_404();
                }

                return code_200(res);
            }

            return code_400()
        }
        else {
            const res = (keys.length > 0) ? await this.get_table(tableName, keys) : await this.get_table(tableName);
            return code_200(res, { "X-Total-Count": res.length });
        }
    }

    /**
     * generic function to process POST requests from the endpoint
     * @param event the event sent by APIGATEWAY
     * @param check_func the function used to check if the data is correctly structured
     * @param tableName the table to interact with 
     */
    async post(event: any, check_func: (obj: any) => boolean, tableName: any) {
        const reqBody: any = JSON.parse(event.isBase64Encoded ? Buffer.from(event.body, "base64").toString() : event.body);

        if (reqBody !== null && check_func(reqBody)) {

            const id = v4();
            const addition = {
                id: id,
                ...reqBody
            };

            await clientDyn.put({
                TableName: tableName,
                Item: addition
            }).promise();

            return code_200(addition);

        }
        else {
            return code_400();
        }
    }

    /**
     * generic function to process DEL requests from the endpoint
     * @param event the event sent by APIGATEWAY
     * @param tableName the table to interact with 
     */
    async del(event: any, tableName: any) {

        if (event.pathParameters !== null &&
            event.pathParameters.hasOwnProperty("id") &&
            event.pathParameters.id != null &&
            this.check_id_in_table(event.pathParameters.id, tableName)
        ) {
            const res = await clientDyn.delete({
                TableName: tableName,
                Key: {
                    id: event.pathParameters.id
                }
            }).promise();
            return code_200();
        }
        else {
            return code_404();
        }
    }

    /**
     * generic function to process PUT requests from the endpoint
     * @param event the event sent by APIGATEWAY
     * @param check_func the function used to check if the data is correctly structured
     * @param tableName the table to interact with 
     */
    async put(event: any, check_func: (obj: any) => boolean, tableName: any) {
        const reqBody: any = JSON.parse(event.isBase64Encoded ? Buffer.from(event.body, "base64").toString() : event.body);

        if (event.pathParameters !== null &&
            event.pathParameters.hasOwnProperty("id") &&
            event.pathParameters.id != null &&
            this.check_id_in_table(event.pathParameters.id, tableName)
        ) {
            if (reqBody != null && check_func(reqBody) && reqBody.id == event.pathParameters.id) {
                const res = await clientDyn.put({
                    TableName: tableName,
                    Item: reqBody
                }).promise();
                return code_200(res);
            }
            else {
                return code_400({
                    req: reqBody,
                    reqBody: reqBody != null,
                    check: check_func(reqBody),
                    reqid: reqBody.id == event.pathParameters.id,
                    event: event
                });
            }
        }
        else {
            return code_404();
        }
    }

    /**
     * generic function to create an APIGATEWAY handler
     * @param tableName the name of the table that the handler will interact with
     * @param check_post the function used to check data structure for post operations
     * @param check_put the function used to check data structure for put operations
     * @param keys_get the attributes of the records to querry for the get operations, empty one will get all the attributes
     * @param crud_func an object having the get, put, post, del functions for the handler
     */
    basic_crud_handler(tableName: any, check_post: (obj: any) => boolean, check_put: (obj: any) => boolean, keys_get: string[] = [], crud_func: ICRUDFunc) {
        return async (event: any) => {
            const auth = this.isAllowed(event);
            if (auth == null) {
                return code_403();
            }
            if (!this.isAllowed(event)) {
                return code_401();
            }
            if (event.requestContext.httpMethod == "GET") {
                return await crud_func["get"](event, tableName, keys_get);
            }

            if (event.requestContext.httpMethod == "POST") {
                return await crud_func["post"](event, check_post, tableName);
            }

            if (event.requestContext.httpMethod == "DELETE") {
                return await crud_func["del"](event, tableName);
            }

            if (event.requestContext.httpMethod == "PUT") {
                return await crud_func["put"](event, check_put, tableName);
            }

            return code_500();
        };
    }

    /**
     * wrapper function to basic_crud_handler to return a basic handler with less params
     * @param tableName the name of the table that the handler will interact with
     * @param check_post the function used to check data structure for post operations
     * @param check_put the function used to check data structure for put operations
     * @param keys_get the attributes of the records to querry for the get operations, empty one will get all the attributes
     */
    base_handler(tableName: any, check_post: (obj: any) => boolean, check_put: (obj: any) => boolean, keys_get: string[] = []) {

        const crud: ICRUDFunc = {
            get: this.get,
            put: this.put,
            post: this.post,
            del: this.del
        }

        return this.basic_crud_handler(tableName, check_post, check_put, keys_get, crud);
    }

    /******************
     * auth functions *
     ******************/

     /**
      * a login function that returns a token corresponding to the user.
      * it contains the user id, the username and the user role.
      * @param username username
      * @param password password
      */
    async auth(username: string, password: string) {
        const arr: any[] = await this.get_table(this.USER_TABLE_NAME);
        const user: any = arr.find((u: any) => u.username == username && u.password == password);
        if (!user) {
            throw new Error("username or password is incorrect");
        }
        const token = jwt.sign({ sub: user.id, usr: user.username, role: user.role }, this.config.secret);
        return token;
    }

    /**
     * a function to check the integrity of the bearer token in the event.
     * returns true if it's correct.
     * @param event the event to check
     */
    check_bearer_struct(event: any) {
        if (!event.headers.hasOwnProperty("Authorization") || event.headers.Authorization == null) {
            return false;
        }
        const bearer_string = event.headers.Authorization;

        const bearer_parts = bearer_string.split(" ");
        if (bearer_parts.length != 2 || !bearer_parts.includes("Bearer")) {
            return false;
        }

        return true;
    }

    /**
     * simple function to get the token, will cause troubles if called before proper
     * structure check.
     * @param event the event containing the token
     */
    get_token(event: any) {
        //check on the Authorization field must be performed before calling this function
        return event.headers.Authorization.split(" ")[1];
    }

    
    /**
     * function used to check either path authorization or method authorization in isAllowed
     * as defined in user_roles.json in the bot folder.
     * @param array is either the array containing allowed paths or the array containing allowed methods
     * @param str is either a path to check or a method to check
     */
    check_auth = (array: string[], str: string) => {
        if (array.includes(str)) {
            return true;
        }
        else {
            return array.includes("*");
        }
    }

    /**
     * function to know if a token is allowed or not
     * @param event event containing the token to check
     */
    isAllowed(event: any) {

        //check if bearer token is present
        if (!this.check_bearer_struct(event)) {
            return false;
        }

        console.log(event);

        const token: string = this.get_token(event);
        const path = event.path;
        const httpMethod: string = event.requestContext.httpMethod;
        const roles: any = this.auth_roles.roles;
        let decodedToken: any;

        //check if token is valid
        try {
            decodedToken = jwt.verify(token, this.config.secret);
        }
        catch (error) {
            return false;
        }

        const role = decodedToken.role;

        //check if authentified used is supposed to access the resource
        if (
            !roles.hasOwnProperty(role) ||
            !(this.check_auth(roles[role]["paths"], path) && this.check_auth(roles[role]["methods"], httpMethod))
        ) {
            return null;
        }
        const currentTime: number = new Date().getTime() / 1000;
        //check the expiration date of a token, if delay accorded in config is negative, no expiration possible
        if (decodedToken.decayPeriod > 0 && (decodedToken.iat + decodedToken.decayPeriod) < currentTime) {
            return false;
        }

        //allow the access to the resource
        return true;
    }
}
