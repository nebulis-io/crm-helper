import * as awsSDK from "aws-sdk";
import { v4 } from 'uuid';
import jwt from "jsonwebtoken";


export interface ICRUDFunc {
    get(event: any, tableName: any, keys: string[]): any;
    post(event: any, check_func: (obj: any) => boolean, tableName: any): any;
    del(event: any, tableName: any): any;
    put(event: any, check_func: (obj: any) => boolean, tableName: any): any;
}

export interface IClient{
    last_name: string;
    first_name: string;
    email: string;
    id: string;
}
export interface IMission{
    mission_name: string;
    client: string;
    documents: string[];
}
export interface IDocument{
    id: string;
    file_name: string;
}

/**
 * http codes
 */
const code_200 = (res: any = { message: "ok" }, headers: any = {}) => {
    return {
        statusCode: 200,
        body: JSON.stringify(res),
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
            "Access-Control-Allow-Headers": "Content-Type",
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
            "Access-Control-Allow-Headers": "Content-Type",
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
            "Access-Control-Allow-Headers": "Content-Type",
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
            "Access-Control-Allow-Headers": "Content-Type",
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
            "Access-Control-Allow-Headers": "Content-Type",
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
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Expose-Headers": "X-Total-Count"
        }
    };
}

export const clientDyn = new awsSDK.DynamoDB.DocumentClient();

export default class helper {
    code_200: (res?: any, headers?: any) => { statusCode: number; body: string; headers: any; };
    code_400: (res?: any) => { statusCode: number; body: string; headers: { "Access-Control-Allow-Origin": string; "Access-Control-Allow-Methods": string; "Access-Control-Allow-Headers": string; "Access-Control-Expose-Headers": string; }; };
    code_401: (res?: any) => { statusCode: number; body: string; headers: { "Access-Control-Allow-Origin": string; "Access-Control-Allow-Methods": string; "Access-Control-Allow-Headers": string; "Access-Control-Expose-Headers": string; }; };
    code_403: (res?: any) => { statusCode: number; body: string; headers: { "Access-Control-Allow-Origin": string; "Access-Control-Allow-Methods": string; "Access-Control-Allow-Headers": string; "Access-Control-Expose-Headers": string; }; };
    code_404: (res?: any) => { statusCode: number; body: string; headers: { "Access-Control-Allow-Origin": string; "Access-Control-Allow-Methods": string; "Access-Control-Allow-Headers": string; "Access-Control-Expose-Headers": string; }; };
    code_500: (res?: any) => { statusCode: number; body: string; headers: { "Access-Control-Allow-Origin": string; "Access-Control-Allow-Methods": string; "Access-Control-Allow-Headers": string; "Access-Control-Expose-Headers": string; }; };
    USER_TABLE_NAME: string;
    config: { secret: string; };
    auth_roles: { roles: any; };

    constructor(USER_TABLE_NAME: string, CONFIG: string, AUTH_ROLES: string) {
        this.code_200 = code_200;
        this.code_400 = code_400;
        this.code_401 = code_401;
        this.code_403 = code_403;
        this.code_404 = code_404;
        this.code_500 = code_500;
        this.USER_TABLE_NAME = USER_TABLE_NAME;
        this.config = JSON.parse(CONFIG);
        this.auth_roles = JSON.parse(AUTH_ROLES);
    }
    /**
     * helper
     */

    check(arr: string[], obj: any) {
        console.log("obj", obj);
        for (let key of arr) {
            if (!(obj.hasOwnProperty(key))) {
                console.log("clé fausse");
                return false;
            }
            if (obj[key] == null) {
                console.log("obj null");
                return false;
            }

            if (typeof obj[key] == "string" && obj[key].length == 0) {
                console.log("chaine vide");
                return false;
            }
        }

        return true;
    }

    async check_id_in_table(id: string, table: any) {
        
        const res = await clientDyn.scan({
            TableName: table.name.get(),
            AttributesToGet: ["id"],
        }).promise().then(result => result.Items?.map(item => item.id));
        return res!.includes(id);
    }

    async get_table(tableName: any, keys: string[] = []) {

        const table_data = (keys.length > 0) ? { TableName: tableName, AttributesToGet: keys } : { TableName: tableName };

        const res = await clientDyn.scan(table_data).promise().then((result: any) => result.Items);
        return res;
    }

    async get_element_by_id(id: string, tableName: any, keys: string[] = []) {

        if (!this.check_id_in_table(id, tableName)) {
            return null;
        }
        const table_data = (keys.length > 0) ? {
            TableName: tableName,
            AttributesToGet: keys,
            Key: {
                id: id
            }
        } : {
                TableName: tableName,
                Key: {
                    id: id
                }
            };


        const res = await clientDyn.get(table_data).promise().then(result => result.Item);

        return res;
    }

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
    async auth(username: string, password: string) {
        const arr: any[] = await this.get_table(this.USER_TABLE_NAME);
        const user: any = arr.find((u: any) => u.username == username && u.password == password);
        if (!user) {
            throw new Error("username or password is incorrect");
        }
        const token = jwt.sign({ sub: user.id, usr: user.username, role: user.role }, this.config.secret);
        return token;
    }

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

    get_token(event: any) {
        //check on the Authorization field must be performed before calling this function
        return event.headers.Authorization.split(" ")[1];
    }

    //used to check either path authorization or method authorization in isAllowed
    check_auth = (array: string[], str: string) => {
        if (array.includes(str)) {
            return true;
        }
        else {
            return array.includes("*");
        }
    }

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

//reexport imports to minimize the import sources in other places
export const uuidv4 = v4;