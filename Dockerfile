FROM node:19-slim
WORKDIR /app
RUN npm i -g typescript
COPY ./tsconfig.json ./
COPY ./package*.json ./
RUN npm i
COPY ./assets ./assets
COPY ./src ./src
RUN tsc -b .
ENTRYPOINT [ "node", "./dist/index.js" ]