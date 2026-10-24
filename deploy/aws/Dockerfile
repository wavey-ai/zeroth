FROM rust:1.96-bullseye AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p zeroth-aws-authorizer

FROM scratch
COPY --from=build /src/target/release/bootstrap /bootstrap
