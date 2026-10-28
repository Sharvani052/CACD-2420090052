module.exports = {
    windowHours: Number(process.env.RISK_WINDOW_HOURS || 24),

    thresholds: {
        medium: Number(process.env.RISK_MEDIUM_THRESHOLD || 30),
        high: Number(process.env.RISK_HIGH_THRESHOLD || 60)
    },

    weights: {
        failedLogin: {
            one: 10,
            repeated: 30,
            severe: 60
        },

        fileAccess: {
            elevated: 10,
            high: 25
        },

        download: {
            elevated: 15,
            high: 25
        },

        ipChange: 15,
        deviceChange: 10
    },

    limits: {
        failedRepeated: 3,
        failedSevere: 5,

        filesElevated: 5,
        filesHigh: 10,

        downloadsElevated: 3,
        downloadsHigh: 5
    }
};