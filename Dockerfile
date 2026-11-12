FROM denoland/deno:alpine
WORKDIR /app
COPY main.ts .
EXPOSE 8000
CMD ["run", "--allow-net", "--allow-env", "main.ts"]
