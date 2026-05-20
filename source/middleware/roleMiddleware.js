const roleMiddleware = (allowedRole) => {
  return (req, res, next) => {
    if (req.user.role !== allowedRole) {
      return res.send("access is denied");
    }
    next();
  };
};
export default roleMiddleware;
