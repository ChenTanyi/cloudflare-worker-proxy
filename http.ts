function validateMethodAndUrl(method: string, url: string): boolean {
    if (method && /^https?:\/\//.test(url)) {
        return true;
    }
    return false;
}

async function sendRequest(method: string, url: string, headers: { [key: string]: string }, body: string | ArrayBuffer | null): Promise<Response> {
    if (!validateMethodAndUrl(method, url)) {
        return new Response(`Unexpected method(${method}) or url(${url})`, {
            status: 400,
            headers: {
                'Content-Type': 'text/plain; charset=utf-8',
            },
        });
    }
    return fetch(url, {
        method: method,
        headers: headers,
        body: body,
    });
}

async function handle(request: Request): Promise<Response> {
    if (request.method == 'GET') {
        let url = new URL(request.url);
        let requestUrl = url.pathname + url.search;
        requestUrl = requestUrl.replace(/^\/*(https?:)(\/*)/, '$1//');
        return sendRequest('GET', requestUrl, {}, null);
    } else if (request.method == 'POST') {
        let param = await request.json<any>();
        if (param.body_encode == 'base64') {
            return sendRequest(param.method, param.url, param.headers, Uint8Array.from(atob(param.body), c => c.charCodeAt(0)));
        } else {
            return sendRequest(param.method, param.url, param.headers, param.body);
        }
    } else {
        return new Response(`Method ${request.method} not allowed.`, {
            status: 405,
            headers: {
                'Content-Type': 'text/plain; charset=utf-8',
                'Allow': 'GET, POST',
            },
        });
    }
}

export default {
    fetch(request: Request) {
        return handle(request);
    }
}