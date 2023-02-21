/** Tomcat web backend endpoint name when deploying WAR file */
export const HOST_ADDRESS: string = "nvip_ui-1.0/";
/** proxy routes to each web backend servlet */
export const Routes = {
  login: HOST_ADDRESS + "loginServlet",
  vulnerability: HOST_ADDRESS + "vulnerabilityServlet",
  main: HOST_ADDRESS + "mainServlet",
  review: HOST_ADDRESS + "reviewServlet",
  search: HOST_ADDRESS + "searchServlet"
}
