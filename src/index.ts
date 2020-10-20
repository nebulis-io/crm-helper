import * as AWS from "aws-sdk";
import { v4 } from 'uuid';
import jwt from "jsonwebtoken";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda"

export type GenericObject = { [key: string]: any };
export type Headers = { [header: string]: boolean | number | string };
export type CheckFunction = (obj: GenericObject) => boolean;
export type ResponseMaker = (res?: GenericObject, headers?: Headers) => APIGatewayProxyResult;

export interface ICRUDFunc {
    get: (event: APIGatewayProxyEvent, tableName: string, keys: string[]) => Promise<APIGatewayProxyResult>;
    post: (event: APIGatewayProxyEvent, tableName: string, check_func: CheckFunction) => Promise<APIGatewayProxyResult>;
    del: (event: APIGatewayProxyEvent, tableName: string) => Promise<APIGatewayProxyResult>;
    put: (event: APIGatewayProxyEvent, tableName: string, check_func: CheckFunction) => Promise<APIGatewayProxyResult>;
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
const make_response = (code: number, res: GenericObject, headers: Headers = {}): APIGatewayProxyResult => {
    return {
        statusCode: code,
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


export const code_200: ResponseMaker = (res, headers) => make_response(200, res || { message: "ok" }, headers);
export const code_400: ResponseMaker = (res, headers) => make_response(400, res || { error: "bad request" }, headers);
export const code_401: ResponseMaker = (res, headers) => make_response(401, res || { error: "unautorized" }, headers);
export const code_403: ResponseMaker = (res, headers) => make_response(403, res || { error: "forbidden" }, headers);
export const code_404: ResponseMaker = (res, headers) => make_response(404, res || { error: "not found" }, headers);
export const code_500: ResponseMaker = (res, headers) => make_response(500, res || { error: "could not process the request" }, headers);

export const clientDyn = new AWS.DynamoDB.DocumentClient();


/**
 * helper class to avoid exporting each function manually
 */
export default class helper {
    userTableName: string;   //table containing the users for the auth part of this package
    config: { secret: string; }; //secret for the token gen
    auth_roles: { roles: { [role_name: string]: { methods: string[], paths: string[], decayPeriod: number } }; }; // object containing the roles defined for the auth check

    constructor(userTableName: string, config: string, authRoles: string) {
        this.userTableName = userTableName;
        this.config = JSON.parse(config); //parsing because it's a process.env variable
        this.auth_roles = JSON.parse(authRoles); //parsing because the auth roles are passed via process.env so it must be a string

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
    check(arr: string[], obj: GenericObject) {
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
     * Check if id exists in table
     * @param id id to check
     * @param table table to check in
     * @returns boolean stating if id exists in table
     */
    async check_id_in_table(id: string, tableName: string): Promise<boolean | undefined> {
        return clientDyn.scan({
            TableName: tableName,
            AttributesToGet: ["id"],
        }).promise()
            .then(result => result.Items?.map(item => item.id))
            .then(ids => ids?.includes(id));
    }

    /**
     * generic function to get all the records attributes
     * @param tableName the table to get all the records
     * @param keys attributes of the records: if the array is empty,
     * @returns all the attributes of the records
     */
    get_table(tableName: string, keys: string[] = []): Promise<AWS.DynamoDB.DocumentClient.ItemList | undefined> {
        const table_data = {
            TableName: tableName,
            AttributesToGet: (keys.length > 0) ? keys : undefined
        };

        return clientDyn.scan(table_data).promise().then(result => result.Items);
    }

    /**
     * generic function to get an element by its id
     * @param id the id of the record to get
     * @param tableName the table to look in
     * @param keys the attributes to get, an empty array will get all the attributes
     */
    async get_element_by_id(id: string, tableName: string, keys: string[] = []) {
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
    async get(event: APIGatewayProxyEvent, tableName: string, keys: string[] = []): Promise<APIGatewayProxyResult> {

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
            const res = await this.get_table(tableName, keys);
            if (res === undefined) {
                return code_500({ error: "Table scan failed" });
            }
            return code_200(res, { "X-Total-Count": res.length });
        }
    }

    /**
     * generic function to process POST requests from the endpoint
     * @param event the event sent by APIGATEWAY
     * @param check_func the function used to check if the data is correctly structured
     * @param tableName the table to interact with 
     */
    async post(event: APIGatewayProxyEvent, tableName: string, check_func: CheckFunction): Promise<APIGatewayProxyResult> {
        if (event.body === null) {
            throw new Error("Null body");
        }
        const reqBody = JSON.parse(event.isBase64Encoded ? Buffer.from(event.body, "base64").toString() : event.body);

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
    async del(event: APIGatewayProxyEvent, tableName: string): Promise<APIGatewayProxyResult> {

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
    async put(event: APIGatewayProxyEvent, tableName: string, check_func: CheckFunction): Promise<APIGatewayProxyResult> {
        if (event.body === null) {
            throw new Error("Null body");
        }
        const reqBody = JSON.parse(event.isBase64Encoded ? Buffer.from(event.body, "base64").toString() : event.body);

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
    basic_crud_handler(crud_func: ICRUDFunc, tableName: string, check_post: CheckFunction, check_put: CheckFunction, keys_get: string[] = []) {
        return async (event: APIGatewayProxyEvent) => {
            const auth = this.isAllowed(event);
            if (auth == null) {
                return code_403();
            }
            if (!this.isAllowed(event)) {
                return code_401();
            }
            switch (event.requestContext.httpMethod) {
                case "GET":
                    return await crud_func.get(event, tableName, keys_get);
                case "POST":
                    return await crud_func.post(event, tableName, check_post);
                case "DELETE":
                    return await crud_func.del(event, tableName);
                case "PUT":
                    return await crud_func.put(event, tableName, check_put);
                default:
                    return code_500();
            }
        };
    }

    /**
     * wrapper function to basic_crud_handler to return a basic handler with less params
     * @param tableName the name of the table that the handler will interact with
     * @param check_post the function used to check data structure for post operations
     * @param check_put the function used to check data structure for put operations
     * @param keys_get the attributes of the records to querry for the get operations, empty one will get all the attributes
     */
    base_handler(tableName: string, check_post: CheckFunction, check_put: CheckFunction, keys_get: string[] = []) {
        return this.basic_crud_handler({
            get: this.get,
            put: this.put,
            post: this.post,
            del: this.del
        }, tableName, check_post, check_put, keys_get);
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
        const arr = await this.get_table(this.userTableName);
        if (arr === undefined) {
            throw new Error("Can't query user table");
        }
        const user = arr.find(u => u.username == username && u.password == password);
        if (user === undefined) {
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
    check_bearer_struct(event: APIGatewayProxyEvent) {
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
    get_token(event: APIGatewayProxyEvent) {
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
    isAllowed(event: APIGatewayProxyEvent) {

        //check if bearer token is present
        if (!this.check_bearer_struct(event)) {
            return false;
        }

        console.log(event);

        const token = this.get_token(event);
        const path = event.path;
        const httpMethod = event.requestContext.httpMethod;
        const roles = this.auth_roles.roles;
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
            !(this.check_auth(roles[role].paths, path) && this.check_auth(roles[role].methods, httpMethod))
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
