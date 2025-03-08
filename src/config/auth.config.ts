export const authConfig = () => ({
    jwt: {
        secret: process.env.JWT_SECRET,
        expiresIn: process.env.JWT_EXPIRES_IN
    },
    bcrypt: {
        saltOrRounds: process.env.BCRYPT_SALT_OR_ROUNDS
    }
})